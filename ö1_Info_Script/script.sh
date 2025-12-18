#!/bin/bash

#
# Detta script samlar in systeminformation - RECON
#
# Kan användas för följande attacker:
# [Skriv möjliga attacker]
#
# Author: Frans Schartau
# Last Update: 2025-01-01

echo "Välkommen till mitt RECON script för att kontrollera en Linux-miljö"

echo
echo "=== SYSTEMINFO ==="
uname -a
date
df
ps
echo
uptime

echo
env | grep auth.sock
echo
du

echo
echo "=== AKTUELL ANVÄNDARE ==="
echo $USER
w
id
groups

echo
echo "=== ANVÄNDARE MED SHELL ==="
cat /etc/passwd | grep "sh$"


echo
echo "=== NÄTVERK ==="
ip a | grep inet
ifconfig -a | grep -A 1 wlan
echo
echo "=== HÄMTA PUBLIK IP INFO  ==="
curl ipinfo.io/ip
arp

echo
echo "=== RAM ANVÄNDNING  ==="
free -h


echo
echo "=== CPU INFO  ==="
lscpu | grep Core


#
# skriv in dina kommandon för tester
#
