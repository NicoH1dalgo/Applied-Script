\# Linux System Information Gathering Script



\## Description

This bash script automates the collection of system information from Linux environments as part of a reconnaissance (recon) phase in security testing. It gathers data about users, programs, hardware, network configuration, and running services.



\## Purpose

\- Automate system information collection in Linux environments

\- Perform initial reconnaissance for security assessments

\- Identify potential security vulnerabilities such as missing updates

\- Practice basic Linux scripting and command-line skills



\## What It Collects

\- \*\*System Info\*\*: OS version, kernel, architecture

\- \*\*Users\*\*: Current user, accounts with shell access

\- \*\*Hardware\*\*: CPU details, RAM usage

\- \*\*Network\*\*: IP addresses, network interfaces

\- \*\*Environment\*\*: System variables and configurations



\## Usage

```bash

chmod +x script.sh      # Make executable

./script.sh             # Run the script

./script.sh > output.txt # Save output to file

```



\## Requirements

\- Linux operating system (tested on Kali Linux)

\- Bash shell

\- Basic commands: `uname`, `grep`, `ip`, `cat`, etc.



\## Educational Context

This script is part of a cybersecurity course exercise (AS20 - Applied Scripting) focused on understanding Linux system reconnaissance techniques.

