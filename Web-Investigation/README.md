# Web Investigation — Write-up

**Platform:** CyberDefenders
**Category:** Network Forensics
**Tool:** Wireshark
**Date:** November 2026

> I don't include the final answers (flags) here, only how I investigated the capture and what I learned.

---

## Scenario

I'm a SOC analyst at **BookWorld**, an online bookstore. An automated alert fired because of an unusual spike in database queries and server load. My job was to analyze the network traffic, find the attack vector, see how much data was exposed, and check whether the attacker gained deeper access to the server.

**Quick background on the main concepts here:**

- **HTTP** is the protocol browsers use to talk to web servers (requesting pages, submitting forms).
- **SQL injection (SQLi)** is a web attack where the attacker types SQL database commands into a normal input field (like a search box) instead of normal text. If the site is not secure, it runs those commands and leaks or changes data.
- **Web shell** is a small malicious script an attacker uploads to a server so they can run commands on it remotely.

---

## How I approached it

The capture was large (~88,000 packets), so I used Wireshark filters and statistics instead of scrolling.

### 1. Find the attacker

I opened **Statistics → Conversations → IPv4** to see who was talking to who. One external IP had sent a huge number of packets to the web server, while a normal user had only ~50. That spike is the attacker. The server appeared in every conversation (it's the common endpoint everyone connects to).

**Lesson:** in Conversations, the IP sending a far higher volume of packets than everyone else usually stands out as the attacker. Automated attacks generate a lot of traffic.

### 2. Enrich the attacker IP

I looked the attacker's IP up on **AbuseIPDB** to get its geographic origin. The city/country had no business reason to be talking to a bookstore, which on its own is a red flag for a targeted attack.

### 3. Find the vulnerable page

Looking at the attacker's HTTP requests, every attack request went to the same page:

```
GET /search.php?search=...
```

So `search.php` is the vulnerable script. The `?search=` parameter is where the attacker injected SQL instead of a book title.

### 4. Identify the attack and tool

Filtering the attacker's requests, I saw payloads like `' or 1=1`, `UNION ALL SELECT`, and `information_schema`. That's **SQL injection**. The User-Agent header also showed:

```
User-Agent: sqlmap/1.8.3
```

So the attacker used **sqlmap**, an automated SQLi tool — which explains the huge number of requests.

### 5. Follow the data theft

I traced the SQLi step by step. The attacker:

- Tested whether the page was injectable (`book and 1=1` vs `book and 1=2`).
- Listed the databases by querying `INFORMATION_SCHEMA.SCHEMATA` (reads all database names).
- Then enumerated tables and found the one holding user data (a `customers`-style table).

To find specific requests fast, I used filters like:

```
frame contains "schema_name"
```

**Note:** the URIs were URL-encoded (`%20`, `%27`, etc.). I decoded them with **CyberChef → URL Decode** instead of by hand, which avoids mistakes.

### 6. Follow the escalation

After reading data, the attacker went for full control:

- Found a hidden admin directory (`/admin/`) — I focused on this with `http.request.method == POST` to see login attempts.
- Brute-forced the admin login (many POST requests to the login page) until a weak password worked.
- Logged into the admin panel.
- Uploaded a **web shell** (a `.php` script) through the admin upload feature, then accessed it to run commands on the server.

**Important detail I noticed:** the web shell appears twice in the traffic —
- a **POST** to the admin page when the file was *uploaded* (`application/x-php`), and
- a **GET** to `/admin/uploads/<shell>.php` when the attacker *ran* it.

Uploading = POST (sending the file); executing = GET (requesting/opening the page).

---

## The attack chain I reconstructed

```
1. SQL injection on search.php   (sqlmap)
2. List databases                (INFORMATION_SCHEMA.SCHEMATA)
3. Find the users table          (customer data)
4. Discover /admin/ directory
5. Brute-force admin login        (weak password)
6. Upload & run a web shell       (full server control)
```

This goes from a single injectable parameter all the way to full server compromise.

---

## What I learned

- A single unvalidated input (`search.php?search=`) was enough to start the whole breach — input validation really matters.
- The **User-Agent** can reveal the attacker's tooling (here, `sqlmap`). Always check it.
- SQLi database enumeration follows a pattern: **databases → tables → columns → data** (schemata, then tables, then the actual records).
- A weak admin password (`admin`-style) made the brute-force succeed. Strong passwords + login rate-limiting (e.g. Fail2ban) + MFA would have stopped this step.
- The same file showing up as a **POST then a GET** tells a story: uploaded, then executed. Reading requests in order reconstructs the attacker's timeline.
- Always **decode** encoded values (CyberChef URL Decode) before reading or reporting them.

---

## Wireshark filters used

| Filter | What it shows |
|--------|---------------|
| `http` | Web traffic |
| `http.request.method == "POST"` | Logins / form submissions / uploads |
| `http.request.method == "GET"` | Page requests / search queries |
| `ip.addr == <attacker IP> && http` | Only the attacker's web requests |
| `frame contains "schema_name"` | Requests reading database names |
| `http contains ".php"` | Requests involving PHP scripts (e.g. the web shell) |

---

## MITRE ATT&CK

| ID | Technique |
|----|-----------|
| T1190 | Exploit Public-Facing Application (SQL injection) |
| T1110 | Brute Force (admin login) |
| T1505.003 | Server Software Component: Web Shell |
| T1213 | Data from Information Repositories (database contents) |
