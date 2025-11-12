# 🧠 Network Traffic Analysis using C++ (libpcap)

**By:** Team IP Freely 
**Course:** Computer Networks Lab  
**Date:** November 2025  

---

## 📘 Project Overview
This project captures and analyzes live network packets using the **libpcap** library in C++.  
It displays protocol statistics (TCP, UDP, ICMP), identifies top source and destination IPs,  
and detects suspicious IPs based on packet volume.

---

## 🎯 Objectives
- Capture live packets from the network interface.
- Extract and analyze IP and protocol information.
- Count total packets by protocol (TCP/UDP/ICMP).
- Display the top communicating IP addresses.
- Detect suspicious activity (e.g., IPs sending 100+ packets).

---

## 🧰 Tools & Technologies
- **Language:** C++  
- **Library:** libpcap  
- **Platform:** Ubuntu Linux  
- **IDE:** Visual Studio Code  

---

## ⚙️ How to Run

### 1️⃣ Install dependencies
```bash
sudo apt update
sudo apt install libpcap-dev
