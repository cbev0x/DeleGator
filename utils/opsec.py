"""
utils/opsec.py

OPSEC utilities for DeleGator.

Provides:
  - Pre-flight warnings before noisy operations
  - Event ID reference data for each operation type
  - Noise rating system for measuring detection surface
  - Timing utilities beyond what OpsecConfig in ldap.py handles

The event data in this module is what backs the OPSEC documentation
in the README. Every operation maps to concrete Windows Event IDs
so operators know exactly what they're generating before they run it.
"""

import sys
import time
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ---------------------------------------------------------------------------
# Noise rating
# ---------------------------------------------------------------------------

class NoiseLevel(Enum):
    """
    Subjective noise rating for each operation based on event volume
    and how commonly detection rules target those event patterns.

    LOW    — generates minimal events, unlikely to trigger modern rules
    MEDIUM — generates notable events, may trigger in mature environments
    HIGH   — generates significant events, will trigger in tuned environments
    """
    LOW    = auto()
    MEDIUM = auto()
    HIGH   = auto()

    def __str__(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# Operation event map
# ---------------------------------------------------------------------------

@dataclass
class OperationProfile:
    """
    Describes the detection surface of a single DeleGator operation.

    name:        Human-readable operation name
    events:      Windows Event IDs generated and what triggers them
    noise:       Subjective noise rating
    notes:       OPSEC notes for the operator
    mitigations: What reduces noise for this operation
    """
    name:        str
    events:      list[str]
    noise:       NoiseLevel
    notes:       str
    mitigations: list[str] = field(default_factory=list)


# Registry of all DeleGator operations and their detection profiles.
# This is the source of truth for OPSEC warnings and README documentation.
OPERATION_PROFILES: dict[str, OperationProfile] = {

    "ldap_enum_full": OperationProfile(
        name="Full LDAP Enumeration (--all)",
        events=[
            "4662 — Directory Service Object Access (multiple, one per query)",
            "4624 — Logon event if using NTLM auth against LDAP",
        ],
        noise=NoiseLevel.MEDIUM,
        notes=(
            "Full enumeration runs multiple targeted LDAP queries in sequence. "
            "Each query generates 4662 events on the DC. DeleGator uses tight "
            "filters rather than full directory dumps, keeping 4662 volume low "
            "compared to tools like BloodHound's SharpHound collector."
        ),
        mitigations=[
            "Use --delay to space queries over time",
            "Use --slow preset to mimic legitimate AD management traffic",
            "Use Kerberos auth (--ccache) rather than NTLM to avoid 4624 events",
            "Target specific OUs with --search-base rather than querying root",
        ],
    ),

    "ldap_enum_targeted": OperationProfile(
        name="Targeted LDAP Enumeration (single type)",
        events=[
            "4662 — Directory Service Object Access (low volume, 2-4 events)",
        ],
        noise=NoiseLevel.LOW,
        notes=(
            "Single-type queries (--unconstrained, --constrained, or --rbcd only) "
            "generate minimal 4662 events. The tight LDAP filters used by DeleGator "
            "produce significantly less noise than broad enumeration."
        ),
        mitigations=[
            "Use Kerberos auth to avoid NTLM logon events",
        ],
    ),

    "s4u2self": OperationProfile(
        name="S4U2Self Request",
        events=[
            "4769 — Kerberos Service Ticket Request (with S4U-specific ticket options)",
            "4768 — Kerberos TGT Request (only if not using existing ccache)",
        ],
        noise=NoiseLevel.MEDIUM,
        notes=(
            "S4U2Self requests are identifiable in Event 4769 by specific ticket "
            "option flags (0x40810010). Detection rules in Elastic and Sentinel "
            "look for this pattern. Using an existing ccache eliminates the "
            "additional 4768 event from a fresh TGT request."
        ),
        mitigations=[
            "Use --ccache to avoid the AS-REQ (4768) entirely",
            "S4U events are inherent to the technique — cannot be eliminated",
        ],
    ),

    "s4u2proxy": OperationProfile(
        name="S4U2Proxy Request",
        events=[
            "4769 — Kerberos Service Ticket Request (delegation ticket options)",
        ],
        noise=NoiseLevel.MEDIUM,
        notes=(
            "S4U2Proxy generates a single 4769 event for the delegated ticket "
            "request. The ticket options field identifies this as a delegation "
            "request. Combined with S4U2Self this produces two 4769 events "
            "in quick succession which is a detectable pattern."
        ),
        mitigations=[
            "Use --delay between S4U2Self and S4U2Proxy to break the succession pattern",
            "Unavoidable — delegation abuse always produces these events",
        ],
    ),

    "rbcd_write": OperationProfile(
        name="RBCD Attribute Write",
        events=[
            "5136 — Directory Service Object Modified (msDS-AllowedToActOnBehalfOfOtherIdentity)",
            "4662 — Directory Service Object Access",
        ],
        noise=NoiseLevel.HIGH,
        notes=(
            "Writing msDS-AllowedToActOnBehalfOfOtherIdentity generates Event 5136 "
            "which is one of the most specifically detected AD attack events. "
            "Custom and prebuilt detection rules in most SIEM platforms target "
            "this exact attribute modification. This is the highest-noise single "
            "operation in DeleGator."
        ),
        mitigations=[
            "Clean up immediately after exploitation using --cleanup",
            "The 5136 event is inherent — cannot be avoided",
            "Minimise dwell time between write and exploitation",
        ],
    ),

    "rbcd_cleanup": OperationProfile(
        name="RBCD Attribute Cleanup",
        events=[
            "5136 — Directory Service Object Modified (attribute deletion)",
        ],
        noise=NoiseLevel.MEDIUM,
        notes=(
            "Cleaning up RBCD generates another 5136 event for the attribute "
            "deletion. This is preferable to leaving the attribute in place "
            "but operators should be aware the cleanup itself is logged."
        ),
        mitigations=[],
    ),

    "tgt_request": OperationProfile(
        name="TGT Request (AS-REQ)",
        events=[
            "4768 — Kerberos Authentication Service Request",
        ],
        noise=NoiseLevel.LOW,
        notes=(
            "A standard TGT request generates a single 4768 event. This is "
            "normal domain traffic and unlikely to trigger detection on its own. "
            "Using --ccache skips this entirely."
        ),
        mitigations=[
            "Use --ccache to skip TGT request entirely",
        ],
    ),
}


# ---------------------------------------------------------------------------
# OpsecCheck — pre-flight confirmation system
# ---------------------------------------------------------------------------

class OpsecCheck:
    """
    Manages pre-flight OPSEC warnings for operations that generate
    detectable Windows events.

    When --opsec-check is passed, the tool prompts the operator before
    any operation that generates Event IDs above the LOW noise threshold.
    """

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._warned: set[str] = set()

    def check(self, operation_key: str) -> bool:
        """
        Check whether an operation should proceed.

        If opsec_check is disabled, always returns True.
        If already warned for this operation in this session, returns True.
        Otherwise prints the warning and prompts for confirmation.

        Returns True to proceed, False to abort.
        """
        if not self.enabled:
            return True

        if operation_key in self._warned:
            return True

        profile = OPERATION_PROFILES.get(operation_key)
        if not profile:
            return True

        if profile.noise == NoiseLevel.LOW:
            return True

        # Import here to avoid circular import with output.py
        from .output import opsec_warning
        confirmed = opsec_warning(
            action=profile.name,
            events=profile.events,
        )

        if confirmed:
            self._warned.add(operation_key)

        return confirmed

    def check_silent(self, operation_key: str) -> NoiseLevel:
        """
        Return the noise level for an operation without prompting.
        Used by modules to annotate their own output.
        """
        profile = OPERATION_PROFILES.get(operation_key)
        return profile.noise if profile else NoiseLevel.LOW


# ---------------------------------------------------------------------------
# Timing utilities
# ---------------------------------------------------------------------------

def jittered_sleep(base_ms: int, jitter_pct: int = 20) -> None:
    """
    Sleep for base_ms milliseconds with optional jitter.

    Separating this from OpsecConfig.sleep() allows modules to insert
    ad-hoc delays at specific points in an attack chain (e.g. between
    S4U2Self and S4U2Proxy) independently of the global query delay.
    """
    if base_ms <= 0:
        return
    jitter_range = int(base_ms * (jitter_pct / 100))
    actual = base_ms + random.randint(-jitter_range, jitter_range)
    time.sleep(max(0, actual) / 1000.0)


def random_sleep(min_ms: int, max_ms: int) -> None:
    """
    Sleep for a random duration between min_ms and max_ms.
    Used for --slow mode to make traffic patterns less machine-like.
    """
    duration = random.randint(min_ms, max_ms)
    time.sleep(duration / 1000.0)


# ---------------------------------------------------------------------------
# Noise summary printer
# ---------------------------------------------------------------------------

def print_operation_noise(operation_key: str) -> None:
    """
    Print a compact noise summary for an operation.
    Called by modules after completing an operation to inform
    the operator what was generated.
    """
    profile = OPERATION_PROFILES.get(operation_key)
    if not profile:
        return

    noise_color = {
        NoiseLevel.LOW:    "\033[32m",   # green
        NoiseLevel.MEDIUM: "\033[33m",   # amber
        NoiseLevel.HIGH:   "\033[31m",   # red
    }.get(profile.noise, "")
    reset = "\033[0m"

    print(
        f"  \033[36m[noise]\033[0m {profile.name}: "
        f"{noise_color}{profile.noise}{reset}"
    )
    for event in profile.events:
        print(f"          \033[90m• {event}{reset}")


def get_noise_summary(operation_keys: list[str]) -> dict:
    """
    Return a structured noise summary for a set of operations.
    Used to build the OPSEC section of JSON output.
    """
    summary = {
        "operations": [],
        "total_event_types": set(),
        "max_noise": NoiseLevel.LOW,
    }

    noise_order = [NoiseLevel.LOW, NoiseLevel.MEDIUM, NoiseLevel.HIGH]

    for key in operation_keys:
        profile = OPERATION_PROFILES.get(key)
        if not profile:
            continue

        summary["operations"].append({
            "name":   profile.name,
            "noise":  str(profile.noise),
            "events": profile.events,
            "notes":  profile.notes,
        })

        for event in profile.events:
            event_id = event.split("—")[0].strip()
            summary["total_event_types"].add(event_id)

        if noise_order.index(profile.noise) > noise_order.index(summary["max_noise"]):
            summary["max_noise"] = profile.noise

    summary["total_event_types"] = sorted(summary["total_event_types"])
    summary["max_noise"] = str(summary["max_noise"])

    return summary
