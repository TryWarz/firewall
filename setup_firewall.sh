#!/bin/bash

set -e

echo "[+] Mise à jour du système..."
sudo apt update && sudo apt install -y nftables git curl golang

echo "[+] Activation de nftables au démarrage..."
sudo systemctl enable nftables
sudo systemctl start nftables

echo "[+] Clonage du projet Go firewall..."
git clone https://github.com/ton-projet/firewall-go.git
cd firewall-go
go mod tidy
go build -o firewall

echo "[+] Création du service systemd..."
sudo cp /path/to/firewall-go/firewall.service /etc/systemd/system/firewall-go.service

echo "[+] Démarrage du service firewall..."
sudo systemctl daemon-reload
sudo systemctl enable firewall-go
sudo systemctl start firewall-go

echo "[+] L'API REST sera accessible sur http://localhost:8080"

echo "[+] ✅ Pare-feu en place et actif."
