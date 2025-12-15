#!/bin/bash
#
# Detta script samlar in systeminformation - RECON
#
# Kan användas för följande attacker:
# [Skriv möjliga attacker]
#
# Author: Frans Schartau
# Last Update: 2025-01-01


echo "Välkommen till RECON script för att kontrollera en Linux-miljö"

echo
echo "=== SYSTEMINFO ==="
uname -a

echo
echo "=== AKTUELL ANVÄNDARE ==="
echo $USER

echo
echo "=== ANVÄNDARE MED SHELL ==="
grep "sh$" /etc/passwd

echo
echo "=== NÄTVERK ==="
ip a | grep inet

echo
echo "=== Cheat sheet  ==="
curl cheat.sh


