# PsExec Hunt — Write-up

**Platform:** CyberDefenders
**Category:** Network Forensics
**Tool:** Wireshark
**Date:** October 2026

> I don't include the final answers here, only how I investigated the capture and what I learned.

---

## Scenario

An IDS alert flagged suspicious **PsExec** lateral movement on the network. The job was to open the provided PCAP and trace what the attacker did: where they came from, which machines they hit, and how they moved around.

**Quick background on the two things this challenge is about:**

- **SMB** is the Windows protocol used to share files and talk between machines over the network. It usually runs on **port 445**.
- **PsExec** is a tool (originally made by Microsoft for admins) that lets you run commands on another machine over SMB. Attackers abuse it to move from one computer to another — this is called **lateral movement**.

---

## How I approached it

The capture was large (~40,000 packets), so I worked with Wireshark display filters instead of scrolling through everything.

### 1. Find the attacker and the first victim

Since PsExec works over SMB, I filtered for SMB traffic:

Then I looked at who was talking to who. The trick I learned here:

- Whoever sends the **Request** is the one starting the connection → the **client** (the attacker).
- Whoever answers with a **Response**, and is sitting on **port 445**, is the **server** (the victim).

The requests were all coming from one machine, and it was logging in to another one. That told me which machine was the attacker and which was the first victim.

### 2. Get the victim's hostname

An IP address is just a number, so I wanted the actual computer name. During the login (NTLM) process, the machines tell each other their names. I filtered for the login traffic:

In the **NTLMSSP_CHALLENGE** packet (the server's reply during login), I expanded the packet details and found the field **Target Name** — that's the victim's hostname.

### 3. Find the account the attacker used

The username shows up in the login too, but in a different message. In the **NTLMSSP_AUTH** packet (the part where the client actually authenticates), I found the **User name** field — that's the account the attacker logged in with.

### 4. See what the attacker dropped on the victim

PsExec copies a small program to the victim and runs it as a service. I filtered for executable files being written over SMB:

This showed the service executable the attacker created and wrote to the target.

### 5. Which shares were used

Windows has hidden admin shares that end with `$`. I filtered for them:

Looking at the order of the packets, I saw two shares being used for two different jobs:

- **ADMIN$** → the attacker wrote the `.exe` file here (this share points to `C:\Windows`).
- **IPC$** → used for communication / sending commands (no files are stored here — it's like a phone line between the two machines).

### 6. Follow the lateral movement

To see if the attacker jumped to another machine, I checked **Statistics → Conversations → IPv4** to see all the IP pairs. There was a second victim IP, and I got its hostname the same way as step 2 (`ntlmssp` → NTLMSSP_CHALLENGE → Target Name).

---

## The attack chain I reconstructed

- The attacker logged in to the first machine with a compromised account.
- They wrote a PsExec service executable to **ADMIN$** and used **IPC$** to communicate.
- Then they moved laterally to a second machine.

---

## What I learned

- In SMB, **Request = client (attacker)** and the **host on port 445 = server (victim)**. This one rule made it much faster to tell who was who.
- Machine hostnames and usernames can be pulled straight out of the **NTLM login packets** (NTLMSSP_CHALLENGE and NTLMSSP_AUTH).
- PsExec has a clear footprint: **ADMIN$** for dropping the service binary, **IPC$** for communication, and a service `.exe` on the target.
- The compromised account was able to reach ADMIN$, which means it had admin-level rights on the target. The PCAP shows the access, but it doesn't show *how* the account got those rights — confirming that would need the host's Windows event logs. (A good reminder to only state what the evidence actually shows.)

---

## Wireshark filters used

| Filter | What it shows |
|--------|---------------|
| `smb2` | SMB (file sharing) traffic |
| `ntlmssp` | NTLM login / authentication packets |
| `smb2.filename contains ".exe"` | Executable files transferred over SMB |
| `smb2.tree contains "$"` | Connections to hidden admin shares (ADMIN$, IPC$, C$) |

---

## MITRE ATT&CK

| ID | Technique |
|----|-----------|
| T1021.002 | Remote Services: SMB / Windows Admin Shares |
| T1570 | Lateral Tool Transfer |
| T1569.002 | System Services: Service Execution |
