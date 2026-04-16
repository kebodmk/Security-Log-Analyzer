# 🔐 Security Log Analyzer

A simple Python tool that analyzes login logs and identifies suspicious IP addresses based on repeated failed login attempts.

---

## 📌 Features

* Parses log files in `timestamp | IP | status` format
* Support multiple log files(Json, csv, txt, etc.)
* Counts failed login attempts per IP
* Flags IPs with **3+ failures** as suspicious
* Sorts results by most failed attempts
* Outputs results to console and file

---

## 🛠️ Technologies Used

* Python

---

## 📄 Log Format

```
YYYY-MM-DD HH:MM:SS | IP_ADDRESS | STATUS
```

Example:

```
2026-05-04 08:15:23 | 192.168.1.10 | FAILED
2026-05-04 08:15:23 | 192.168.1.32 | SUCCESS
```

## 📤 Output

* Prints suspicious IPs in order, in the terminal
* Saves results to `Suspicious_ips.txt`

---

## 🚀 Future Improvements

* Detect brute-force attacks based on rapid login attempts
* Add data visualization (graphs of failed login trends)
* Support large-scale datasets
* Track additional events (usernames, ports, devices)

---
