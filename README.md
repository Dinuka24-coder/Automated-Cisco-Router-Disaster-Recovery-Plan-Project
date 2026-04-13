# 🛡️ Automated Cisco Network Backup & Security Auditor

**Author:** Dinuka Amarasekara  
**Role:** Network Engineering Intern  
**Tech Stack:** Python 3, Netmiko, Cisco IOS-XE

## 📖 Project Overview
In modern enterprise networks, relying on manual processes for configuration backups and security audits introduces significant risks, including configuration drift and delayed disaster recovery. 

This project bridges **Network Operations** and **Network Security** (DevSecOps). It is a Python-based automation script that securely connects to Cisco enterprise routers over SSH, downloads the running configuration to establish a disaster recovery baseline, and immediately parses the configuration to flag critical security vulnerabilities.

*This tool was developed as a final capstone project during a 6-month Network Engineering internship.*

## ✨ Core Features
* **Secure Programmatic Access:** Utilizes the `netmiko` library to establish secure SSHv2 connections, bypassing legacy and insecure protocols like Telnet.
* **Automated Disaster Recovery:** Automatically issues configuration retrieval commands (`show running-config`) and saves timestamped blueprints locally.
* **Deep-Scan Security Auditing:** Parses hundreds of lines of router configuration in milliseconds to identify misconfigurations against enterprise security baselines.
* **Performance Benchmarking:** Tracks execution time to prove the efficiency of automation vs. manual engineering checks.

## 🔍 The Security Rulebook
The script currently audits the downloaded configuration against the following 7 critical vulnerabilities:
1. **Plaintext Passwords:** Flags the legacy `enable password` command.
2. **Weak Encryption:** Flags easily decipherable Cisco Type 7 passwords.
3. **Default SNMP Strings:** Flags `public` or `private` SNMP community strings.
4. **Unencrypted VTY Lines:** Flags if Telnet transport is permitted.
5. **Unencrypted Web Dashboards:** Flags `ip http server` (HTTP instead of HTTPS).
6. **Disabled Global Encryption:** Flags `no service password-encryption`.
7. **Permissive Firewalls:** Flags overly permissive `permit ip any any` Access Control Lists (ACLs).

## 🚀 Execution & Output
When executed, the script generates a local backup text file and a timestamped security audit report.
