# 🛡️ Simple Python IDS – YouTube Tutorial Series

This repository contains the **full code** from my YouTube tutorial series on building a **basic Intrusion Detection System (IDS)** with Python.
The project is split into **three parts**:

## 📺 YouTube Series

👉 **Part 1** – Building the IDS engine
👉 **Part 2** – Creating a log generator for testing
👉 **Part 3** – Running both scripts together in a live demo

Watch the tutorials here: [🔗 ZeteoSec on YouTube](https://youtube.com/@ZeteoSec)

---

## 📂 Repository Contents

* **part1_ids.py** – Core IDS script that analyzes simulated packets/logs for suspicious patterns like port scans and simple payload attacks.
* **part2_log_generator.py** – Log generator that creates sample traffic and attack patterns for testing the IDS.
* (Optional) Combined demo script from Part 3 once completed.

---

## 🛠️ How to Run

### Requirements

* Python 3.8+
* No external libraries required (standard library only).

### Steps

1. Clone this repo

   ```bash
   git clone https://github.com/<your-username>/simple-python-ids.git
   cd simple-python-ids
   ```
2. Run the IDS engine (Part 1)

   ```bash
   python part1_ids.py
   ```
3. In a second terminal, run the log generator (Part 2)

   ```bash
   python part2_log_generator.py
   ```
4. Watch the IDS detect suspicious activity in real time.

---

## Features

* Detects **port scans** by tracking multiple connections from a single IP.
* Flags **basic payload attacks** (e.g., XSS, SQL injection patterns).
* Fully **commented code** to help beginners follow along.

---

## Purpose

This project was created **for educational purposes only** as part of my cybersecurity learning journey.
It’s meant to show how IDS concepts work under the hood—not to replace professional tools.

---

##  Connect

📺 [Subscribe to ZeteoSec](https://youtube.com/@ZeteoSec) for more Python + Cybersecurity tutorials.
🐦 [Follow on X/Twitter](#) for updates.

---

Would you like me to also draft a **short GitHub commit message** for your initial push (e.g., “Add IDS tutorial Part 1 & 2 scripts”)?
