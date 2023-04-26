#!/bin/bash


sudo apt update -y
sudo apt upgrade -y

sudo apt -y install build-essential
sudo apt -y install sshpass

sudo apt -y install python3-dev
sudo apt -y install python3-pip
python3 -m pip install -U pip


# for Japanese
sudo timedatectl set-timezone Asia/Tokyo
sudo cat << 'EOF' | sudo tee /etc/default/keyboard
# KEYBOARD CONFIGURATION FILE
# Consult the keyboard(5) manual page.
XKBMODEL="pc105"
XKBLAYOUT="jp"
XKBVARIANT=""
XKBOPTIONS=""

BACKSPACE="guess"
EOF