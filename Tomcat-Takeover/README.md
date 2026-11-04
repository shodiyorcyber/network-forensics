# Tomcat Takeover — Network Forensics Writeup

**Platform:** CyberDefenders — Blue Team CTF
**Category:** Network Forensics / PCAP Analysis
**Tools:** Wireshark
**Analyst:** Shodiyor Tuychivoyev

---

## Overview

A web server running **Apache Tomcat** was compromised. Analysis of the captured
traffic (`web server.pcap`) reveals the full attack chain: an active port scan,
directory enumeration, a brute-force against the Tomcat Manager panel, a malicious
`.war` file upload, and finally a reverse shell calling back to the attacker.

This writeup reconstructs each stage from the packet capture.

---

## Attack Timeline

| # | Stage | Finding |
|---|-------|---------|
| 1 | Reconnaissance (port scan) | Attacker IP: `14.0.0.120` |
| 2 | Attribution | Origin country: China |
| 3 | Service discovery | Admin panel port: `8080` |
| 4 | Directory enumeration | Tool used: `gobuster` |
| 5 | Admin interface found | `/manager` |
| 6 | Credential brute-force | `admin:tomcat` |
| 7 | Malicious upload | `JXQOZY.war` |
| 8 | Reverse shell callback | `14.0.0.120:51985` |

---

## Analysis

### 1. Identifying the attacker (port scan)

The capture shows one host sending connection requests across many destination
ports in a short window — the signature of an active port scan. Filtering the
SYN packets isolates the source responsible:

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

The scanning host — the attacker — is **`14.0.0.120`**.

### 2. Attribution

IP enrichment of `14.0.0.120` places the attacker's activity as originating from
**China**.

### 3. Admin panel port

The scan revealed several open ports. Apache Tomcat serves its web interface and
the **Manager** admin panel on **port `8080`**.

### 4. Directory enumeration tool

After mapping open ports, the attacker enumerated directories and files. The
`User-Agent` header in the HTTP requests fingerprints the tool used:

```
http.user_agent contains "gobuster"
```

The enumeration was performed with **gobuster**.

### 5. Admin interface discovered

Among the enumerated paths, the attacker located the Tomcat administrative
interface at **`/manager`** — the Tomcat Manager application used to deploy and
manage web apps.

### 6. Brute-force credentials

Tomcat Manager uses **HTTP Basic Authentication**, so credentials travel in the
`Authorization: Basic <base64>` header of GET requests:

```
http.authorization
```

Decoding the base64 of the successful request (CyberChef → From Base64) reveals
the working credentials: **`admin:tomcat`**.

> Weak/default Tomcat Manager credentials are a classic foothold.

### 7. Malicious file upload

With Manager access, the attacker deployed a malicious web application. A `.war`
file is a packaged Java web app — deploying one through Manager drops executable
code on the server. The uploaded payload was **`JXQOZY.war`**.

### 8. Reverse shell callback

Once deployed, the payload opened a reverse shell back to the attacker. Because
a reverse shell connects *outward* from the victim, the victim server
(`10.0.0.112`) repeatedly initiated connections to a single high port on the
attacker's host.

Confirming the listener side — the machine that **accepts** the connection sends
a SYN-ACK:

```
ip.src == 14.0.0.120 && tcp.flags == 0x012
```

Following the TCP stream shows the `/dev/tcp/<ip>/<port>` redirection. The
callback destination is **`14.0.0.120:51985`**.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active Scanning | T1595 |
| Discovery | Network Service Discovery | T1046 |
| Credential Access | Brute Force | T1110 |
| Execution / Persistence | Server Software Component: Web Shell | T1505.003 |
| Command & Control | Reverse shell callback | T1059 |

---

## Defensive Recommendations

- **Remove or restrict Tomcat Manager** — never expose `/manager` to untrusted
  networks; bind it to localhost or behind a VPN.
- **Replace default/weak credentials** and enforce strong passwords plus lockout
  after failed Basic Auth attempts.
- **Disable remote WAR deployment** in production, or allow it only from trusted
  hosts.
- **Egress filtering** — block outbound connections from the server to arbitrary
  high ports to break reverse-shell callbacks.
- **Monitor** for scanning bursts, repeated 401s on `/manager`, and known
  enumeration User-Agents (gobuster, dirb, etc.).

---

*Lab exercise completed on CyberDefenders. All activity occurred in an isolated
training environment — not a real-world target.*
