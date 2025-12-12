# PERINTAH LENGKAP - Copy paste ini saja
sudo -i && bash <(wget -qO- https://raw.githubusercontent.com/sukronwae85-design/installssh/main/install.sh) --install

ATAU PERINTAH BERTAHAP:
bash

# 1. Login sebagai root
sudo -i

# 2. Download script
wget -O install.sh https://raw.githubusercontent.com/sukronwae85-design/installssh/main/install.sh

# 3. Beri permission
chmod +x install.sh

# 4. Jalankan instalasi
./install.sh --install

📄 FILE YANG PERLU DIUPLOAD KE GITHUB:

Buat file install.sh dengan konten berikut di repository Anda:
bash

#!/bin/bash

# ====================================================
# AUTO INSTALL SSH + VMESS + UDP CUSTOM COMPLETE
# Repository: https://github.com/sukronwae85-design/installssh
# ====================================================

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
VERSION="3.0"
DOMAIN=""
EMAIL=""
SERVER_IP=$(curl -s ifconfig.me)

# Port Configuration
SSH_PORT=22
SSH_ALT_PORT=2222
UDP_PORTS=(7100 7200 7300)
VMESS_PORT=443
VLESS_PORT=80
TROJAN_PORT=8443

# User Limits
MAX_IPS_PER_USER=3
DEFAULT_EXPIRY_DAYS=30

# Paths
CONFIG_DIR="/etc/ssh-vmess-manager"
USER_DB="$CONFIG_DIR/users.db"
LOG_FILE="/var/log/ssh-vmess.log"
BACKUP_DIR="/var/backup/ssh-vmess"

# ====================================================
# INITIALIZATION
# ====================================================

show_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════╗
║      SSH + VMESS AUTO INSTALLER          ║
║         github.com/sukronwae85-design    ║
║                                          ║
║  Features:                               ║
║  • SSH with UDP Custom (7100-7300)       ║
║  • VMESS/VLESS on Port 80/443            ║
║  • IP Limit & Auto Lock System           ║
║  • Auto Backup & Restore                 ║
║  • Complete Monitoring                   ║
╚══════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "Server IP: ${GREEN}$SERVER_IP${NC}"
    echo "══════════════════════════════════════════"
}

init_system() {
    echo -e "${GREEN}[*] Initializing System...${NC}"
    mkdir -p $CONFIG_DIR $BACKUP_DIR
    [[ ! -f $USER_DB ]] && echo '[]' > $USER_DB
    apt-get update -y
    apt-get install -y jq curl wget
    echo -e "${GREEN}[✓] System initialized${NC}"
}

# ====================================================
# INSTALLATION FUNCTIONS
# ====================================================

install_dependencies() {
    echo -e "${GREEN}[*] Installing Dependencies...${NC}"
    apt-get install -y \
        openssh-server nginx certbot \
        python3 python3-pip jq \
        iptables fail2ban cron \
        net-tools htop
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
}

install_ssh() {
    echo -e "${GREEN}[*] Installing SSH Server...${NC}"
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
Port $SSH_ALT_PORT
PermitRootLogin no
MaxAuthTries 3
MaxSessions $MAX_IPS_PER_USER
PasswordAuthentication yes
Banner /etc/ssh-banner.txt
EOF
    
    # Create banner
    cat > /etc/ssh-banner.txt << EOF
================================
SSH Server - Managed by Script
Server: $SERVER_IP
Ports: $SSH_PORT, $SSH_

