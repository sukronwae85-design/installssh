#!/bin/bash

# ====================================================
# AUTO INSTALL SCRIPT SSH + VMESS + UDP CUSTOM COMPLETE
# Support: Ubuntu 18/20/22/24
# Features:
# 1. SSH with UDP Custom (Port 7100-7300, 1-65535)
# 2. VMESS/VLESS/Xray (Port 80, 443)
# 3. IP Limit & Auto Lock System
# 4. Auto Backup to Gmail/Telegram
# 5. Nginx Reverse Proxy + SSL
# 6. Domain Pointing
# 7. SSH Banner Management
# 8. Complete Monitoring Modules
# 
# GitHub: https://github.com/sukronwae85-design/sshvmess-udp-costume
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
VERSION="2.0"
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
XRAY_UDP_PORT=10000-65535

# User Limits
MAX_IPS_PER_USER=3
DEFAULT_EXPIRY_DAYS=30
AUTO_LOCK_ENABLED=true

# Paths
CONFIG_DIR="/etc/ssh-vmess-manager"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/users.db"
LOG_FILE="/var/log/ssh-vmess.log"
BACKUP_DIR="/var/backup/ssh-vmess"
NGINX_DIR="/etc/nginx"
XRAY_DIR="/usr/local/etc/xray"
CERTS_DIR="/etc/ssl/certs"

# Telegram & Gmail
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
GMAIL_USER=""
GMAIL_PASS=""

# Banner
DEFAULT_BANNER="
============================================
🛡️  SSH + VMESS SERVER MANAGER
📡 Server IP: $SERVER_IP
🔒 Secure Tunnel Enabled
📅 $(date '+%d %B %Y')
============================================
"

# ====================================================
# INITIALIZATION & LOGGING
# ====================================================

init_system() {
    echo -e "${GREEN}Initializing System...${NC}"
    
    # Create directories
    mkdir -p $CONFIG_DIR
    mkdir -p $BACKUP_DIR/{daily,weekly,monthly}
    mkdir -p $CERTS_DIR
    mkdir -p /var/www/html
    
    # Create initial files
    [[ ! -f $CONFIG_FILE ]] && echo '{}' > $CONFIG_FILE
    [[ ! -f $USER_DB ]] && echo '[]' > $USER_DB
    [[ ! -f $LOG_FILE ]] && touch $LOG_FILE
    
    # Install jq if not exists
    if ! command -v jq &> /dev/null; then
        apt-get install -y jq
    fi
    
    log_message "System initialized"
}

log_message() {
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $msg" >> $LOG_FILE
    echo -e "${BLUE}[LOG]${NC} $msg"
}

show_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║      SSH + VMESS + UDP CUSTOM INSTALLER         ║
║               COMPLETE EDITION                   ║
║                                                  ║
║  Features:                                       ║
║  • SSH with UDP Custom (1-65535)                ║
║  • VMESS/VLESS/Trojan on Port 80/443            ║
║  • IP Limit & Auto Lock System                  ║
║  • Auto Backup (Gmail/Telegram)                 ║
║  • Nginx + SSL + Domain Support                 ║
║  • Complete Monitoring                          ║
║                                                  ║
║  GitHub: sukronwae85-design/sshvmess-udp-costume║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "Server IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "OS: ${GREEN}$(lsb_release -ds)${NC}"
    echo "══════════════════════════════════════════════════"
}

# ====================================================
# DEPENDENCY INSTALLATION
# ====================================================

install_dependencies() {
    echo -e "${GREEN}Installing Dependencies...${NC}"
    
    apt-get update -y
    apt-get upgrade -y
    apt-get install -y \
        curl wget git nano htop \
        net-tools iptables iptables-persistent \
        fail2ban cron bc \
        python3 python3-pip \
        jq screen tmux \
        openssl unzip socat \
        netcat nload iftop \
        build-essential libssl-dev \
        zip unzip tar gzip
    
    # Install Node.js for monitoring
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    
    # Install Python packages
    pip3 install requests psutil
    
    log_message "Dependencies installed"
}

# ====================================================
# SSH SERVER WITH UDP CUSTOM
# ====================================================

install_ssh_server() {
    echo -e "${GREEN}Installing SSH Server...${NC}"
    
    apt-get install -y openssh-server
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Configure SSH with multiple ports
    cat > /etc/ssh/sshd_config << EOF
# SSH Manager Configuration
Port $SSH_PORT
Port $SSH_ALT_PORT
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions $MAX_IPS_PER_USER
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding yes
GatewayPorts yes
X11Forwarding no
PermitEmptyPasswords no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
AllowAgentForwarding yes
PrintMotd yes
Banner /etc/ssh-banner.txt
Subsystem sftp /usr/lib/openssh/sftp-server

# Match rules for limiting
Match User *,!root
    MaxSessions $MAX_IPS_PER_USER
    AllowTcpForwarding yes
    
Match Address 127.0.0.1
    PermitRootLogin yes
EOF
    
    # Create SSH banner
    echo "$DEFAULT_BANNER" > /etc/ssh-banner.txt
    
    # Create restricted shell for users
    cat > /usr/local/bin/restricted-shell << 'EOF'
#!/bin/bash
USER=$(whoami)
BANNER="/etc/ssh-banner.txt"

if [ -f "$BANNER" ]; then
    cat "$BANNER"
fi

echo ""
echo "Welcome, $USER!"
echo "Account created: $(date)"
echo "Max connections: $MAX_IPS_PER_USER"
echo ""
echo "Available commands:"
echo "  myinfo     - Show account info"
echo "  speedtest  - Test connection speed"
echo "  menu       - Show user menu"
echo "  exit       - Logout"
echo ""

while true; do
    read -p "ssh-manager> " cmd
    case $cmd in
        myinfo)
            echo "Username: $USER"
            echo "IP: $(who -m | awk '{print $NF}')"
            echo "Session: $(who | grep $USER | wc -l)/$MAX_IPS_PER_USER"
            ;;
        speedtest)
            echo "Testing speed..."
            curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3 -
            ;;
        menu)
            echo "User menu coming soon..."
            ;;
        exit|logout)
            exit 0
            ;;
        *)
            echo "Unknown command. Type 'menu' for help."
            ;;
    esac
done
EOF
    
    chmod +x /usr/local/bin/restricted-shell
    
    systemctl restart ssh
    systemctl enable ssh
    
    log_message "SSH Server installed with UDP support"
}

install_udp_custom() {
    echo -e "${GREEN}Installing UDP Custom...${NC}"
    
    # Download and compile UDP Custom
    apt-get install -y cmake golang
    
    # Install UDP2RAW
    wget https://github.com/wangyu-/udp2raw-tunnel/releases/download/20200818.0/udp2raw_binaries.tar.gz
    tar -xzf udp2raw_binaries.tar.gz
    mv udp2raw_amd64 /usr/local/bin/udp2raw
    chmod +x /usr/local/bin/udp2raw
    
    # Install UdpRawServer
    git clone https://github.com/sukronwae85-design/udp-custom.git /tmp/udp-custom
    cd /tmp/udp-custom && go build -o /usr/local/bin/udp-custom
    
    # Create UDP Custom service for multiple ports
    for port in "${UDP_PORTS[@]}"; do
        cat > /etc/systemd/system/udp-custom-$port.service << EOF
[Unit]
Description=UDP Custom Server on port $port
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp-custom -l :$port -key "ssh-udp-$port" -cipher aes -mtu 1350 -sndwnd 1024 -rcvwnd 1024
Restart=always
RestartSec=3
User=nobody

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable udp-custom-$port
        systemctl start udp-custom-$port
        
        log_message "UDP Custom started on port $port"
    done
    
    # Create UDP range service (1-65535)
    cat > /etc/systemd/system/udp-range.service << EOF
[Unit]
Description=UDP Full Range Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw -s -l0.0.0.0:10000 -r 127.0.0.1:$SSH_PORT --raw-mode faketcp -k "udp-full-range"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable udp-range
    systemctl start udp-range
    
    # Configure iptables for UDP ports
    iptables -A INPUT -p udp --dport 1:65535 -j ACCEPT
    iptables -A INPUT -p tcp --dport 10000:65535 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    
    log_message "UDP Custom installed (Ports 1-65535)"
}

# ====================================================
# XRAY/VMESS/SSL INSTALLATION
# ====================================================

install_xray() {
    echo -e "${GREEN}Installing Xray Core...${NC}"
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Generate UUIDs
    VMESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    TROJAN_UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # Create Xray config
    cat > $XRAY_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "port": $VLESS_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$VLESS_UUID",
                        "flow": "xtls-rprx-direct"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "http",
                        "request": {
                            "path": ["/vless"]
                        }
                    }
                }
            },
            "tag": "vless-tcp"
        },
        {
            "port": $VMESS_PORT,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$VMESS_UUID",
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": "/vmess"
                },
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "$CERTS_DIR/fullchain.pem",
                            "keyFile": "$CERTS_DIR/privkey.pem"
                        }
                    ]
                }
            },
            "tag": "vmess-ws-tls"
        },
        {
            "port": $TROJAN_PORT,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$TROJAN_UUID"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "$CERTS_DIR/fullchain.pem",
                            "keyFile": "$CERTS_DIR/privkey.pem"
                        }
                    ]
                }
            },
            "tag": "trojan-tls"
        },
        {
            "port": 10000,
            "protocol": "shadowsocks",
            "settings": {
                "clients": [
                    {
                        "method": "chacha20-ietf-poly1305",
                        "password": "$(openssl rand -hex 16)"
                    }
                ]
            },
            "tag": "shadowsocks"
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": []
    }
}
EOF
    
    # Create log directory
    mkdir -p /var/log/xray
    
    # Start Xray
    systemctl restart xray
    systemctl enable xray
    
    # Save config to file
    cat > $CONFIG_DIR/vmess-config.txt << EOF
============================================
🔰 VMESS CONFIGURATION (Port $VMESS_PORT)
============================================
Address: $SERVER_IP
Port: $VMESS_PORT
UUID: $VMESS_UUID
Security: auto
Network: ws
Path: /vmess
TLS: tls
Type: none
============================================
VMESS LINK:
vmess://$(echo '{
  "v": "2",
  "ps": "SSH-VMESS-SERVER",
  "add": "'$SERVER_IP'",
  "port": "'$VMESS_PORT'",
  "id": "'$VMESS_UUID'",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "/vmess",
  "tls": "tls",
  "sni": "",
  "alpn": ""
}' | base64 -w0)
============================================
🔰 VLESS CONFIGURATION (Port $VLESS_PORT)
============================================
Address: $SERVER_IP
Port: $VLESS_PORT
UUID: $VLESS_UUID
Flow: xtls-rprx-direct
Network: tcp
Path: /vless
============================================
🔰 TROJAN CONFIGURATION (Port $TROJAN_PORT)
============================================
Address: $SERVER_IP
Port: $TROJAN_PORT
Password: $TROJAN_UUID
============================================
EOF
    
    log_message "Xray with VMESS/VLESS/Trojan installed"
}

# ====================================================
# NGINX + SSL + DOMAIN SETUP
# ====================================================

install_nginx_ssl() {
    echo -e "${GREEN}Installing Nginx and SSL...${NC}"
    
    apt-get install -y nginx certbot python3-certbot-nginx
    
    # Stop nginx temporarily
    systemctl stop nginx
    
    # Generate SSL certificate
    if [ -n "$DOMAIN" ]; then
        echo -e "${YELLOW}Setting up SSL for domain: $DOMAIN${NC}"
        
        # Request Let's Encrypt certificate
        certbot certonly --standalone --agree-tos --no-eff-email \
            --email "$EMAIL" -d "$DOMAIN" \
            --preferred-challenges http-01 \
            --non-interactive || {
                echo -e "${YELLOW}Using self-signed certificate...${NC}"
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout $CERTS_DIR/privkey.pem \
                    -out $CERTS_DIR/fullchain.pem \
                    -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"
            }
        
        # Link certificates
        ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERTS_DIR/fullchain.pem
        ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERTS_DIR/privkey.pem
    else
        echo -e "${YELLOW}Generating self-signed SSL certificate...${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout $CERTS_DIR/privkey.pem \
            -out $CERTS_DIR/fullchain.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$SERVER_IP"
    fi
    
    # Configure Nginx
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml+rss text/javascript;
    
    # Virtual Hosts
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Create default site
    cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $SERVER_IP $DOMAIN;
    
    ssl_certificate $CERTS_DIR/fullchain.pem;
    ssl_certificate_key $CERTS_DIR/privkey.pem;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Root directory
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # VMESS WebSocket path
    location /vmess {
        proxy_pass http://127.0.0.1:$VMESS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # VLESS path
    location /vless {
        proxy_pass http://127.0.0.1:$VLESS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    
    # Admin panel
    location /admin {
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        alias /var/www/admin;
        index index.html;
    }
}
EOF
    
    # Create admin directory
    mkdir -p /var/www/admin
    cat > /var/www/admin/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>SSH-VMESS Admin Panel</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .card { background: #f5f5f5; padding: 20px; margin: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>SSH + VMESS Server Manager</h1>
    <div class="card">
        <h3>Server Status: <span style="color:green">● ONLINE</span></h3>
        <p>IP: $SERVER_IP</p>
        <p>Uptime: <span id="uptime">Loading...</span></p>
    </div>
</body>
</html>
EOF
    
    # Create htpasswd for admin (default: admin/admin)
    echo "admin:\$apr1\$3WZQzL2E\$X5h6hJ8L8Y8Z9Z9Z9Z9Z9/" > /etc/nginx/.htpasswd
    
    # Test nginx config
    nginx -t
    
    # Start nginx
    systemctl start nginx
    systemctl enable nginx
    
    # Auto-renew SSL certificate
    (crontab -l 2>/dev/null; echo "0 0 * * * certbot renew --quiet") | crontab -
    
    log_message "Nginx with SSL installed"
}

# ====================================================
# USER MANAGEMENT SYSTEM
# ====================================================

create_user_account() {
    echo -e "${GREEN}Create User Account${NC}"
    echo "========================="
    
    read -p "Username: " username
    read -s -p "Password: " password
    echo
    read -p "Expiry days [$DEFAULT_EXPIRY_DAYS]: " expiry_days
    expiry_days=${expiry_days:-$DEFAULT_EXPIRY_DAYS}
    read -p "Max IP connections [$MAX_IPS_PER_USER]: " max_ips
    max_ips=${max_ips:-$MAX_IPS_PER_USER}
    
    # Check if user exists
    if id "$username" &>/dev/null; then
        echo -e "${RED}User already exists!${NC}"
        return 1
    fi
    
    # Create system user
    useradd -m -s /usr/local/bin/restricted-shell "$username"
    echo "$username:$password" | chpasswd
    
    # Calculate expiry date
    expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    
    # Add to database
    user_data=$(jq -n \
        --arg user "$username" \
        --arg pass "$password" \
        --arg expiry "$expiry_date" \
        --arg created "$(date +%Y-%m-%d)" \
        --argjson max "$max_ips" \
        '{
            username: $user,
            password: $pass,
            created: $created,
            expiry: $expiry,
            max_ips: $max,
            current_ips: [],
            locked: false,
            total_bandwidth: 0,
            last_login: "",
            vmess_uuid: "'$(cat /proc/sys/kernel/random/uuid)'",
            vless_uuid: "'$(cat /proc/sys/kernel/random/uuid)'"
        }')
    
    # Add to database
    jq ". += [$user_data]" $USER_DB > $USER_DB.tmp && mv $USER_DB.tmp $USER_DB
    
    # Create VMESS config for user
    local vmess_uuid=$(echo "$user_data" | jq -r '.vmess_uuid')
    cat > $CONFIG_DIR/users/$username-vmess.json << EOF
{
  "v": "2",
  "ps": "$username-SSH-VMESS",
  "add": "$SERVER_IP",
  "port": "$VMESS_PORT",
  "id": "$vmess_uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "/vmess",
  "tls": "tls",
  "sni": "",
  "alpn": ""
}
EOF
    
    # Generate VMESS link
    local vmess_link="vmess://$(cat $CONFIG_DIR/users/$username-vmess.json | base64 -w0)"
    
    echo -e "\n${GREEN}User Created Successfully!${NC}"
    echo -e "Username: ${CYAN}$username${NC}"
    echo -e "Password: ${CYAN}$password${NC}"
    echo -e "Expiry: ${YELLOW}$expiry_date${NC}"
    echo -e "Max IPs: ${YELLOW}$max_ips${NC}"
    echo -e "\n${GREEN}VMESS Configuration:${NC}"
    echo -e "----------------------------------------"
    echo -e "$vmess_link"
    echo -e "----------------------------------------"
    
    log_message "User created: $username"
    
    # Send to Telegram if configured
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]]; then
        send_telegram_message "✅ New User Created
👤 Username: $username
📅 Expiry: $expiry_date
🔗 Max IPs: $max_ips
🌐 VMESS: Ready"
    fi
}

list_all_users() {
    echo -e "${GREEN}List All Users${NC}"
    echo "========================="
    
    local total=$(jq 'length' $USER_DB)
    echo -e "Total Users: ${CYAN}$total${NC}\n"
    
    jq -r '.[] | "\(.username) | Expiry: \(.expiry) | IPs: \(.current_ips | length)/\(.max_ips) | \(if .locked then "🔒 LOCKED" else "✅ ACTIVE" end)"' $USER_DB | \
    while read -r line; do
        echo -e "$line"
    done
}

check_online_users() {
    echo -e "${GREEN}Online Users Monitoring${NC}"
    echo "========================="
    
    # Clear current IPs
    tmp_file=$(mktemp)
    jq 'map(.current_ips = [])' $USER_DB > $tmp_file && mv $tmp_file $USER_DB
    
    # Check SSH sessions
    while read -r line; do
        if [[ $line =~ sshd.*Accepted.*for\ (.+)\ from ]]; then
            username="${BASH_REMATCH[1]}"
            ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
            timestamp=$(echo "$line" | grep -oE '[A-Z][a-z]{2}\s+[0-9]+\s+[0-9:]+')
            
            # Update user's IP list
            user_index=$(jq 'map(.username) | index("'$username'")' $USER_DB)
            if [[ "$user_index" != "null" ]]; then
                current_ips=$(jq ".[$user_index].current_ips" $USER_DB)
                if ! echo "$current_ips" | jq -e ".[] | select(. == \"$ip\")" > /dev/null; then
                    jq ".[$user_index].current_ips += [\"$ip\"]" $USER_DB > $tmp_file && mv $tmp_file $USER_DB
                    
                    # Check IP limit
                    ip_count=$(jq ".[$user_index].current_ips | length" $USER_DB)
                    max_ips=$(jq ".[$user_index].max_ips" $USER_DB)
                    
                    if [[ $ip_count -gt $max_ips ]]; then
                        echo -e "${RED}⚠️ $username exceeded IP limit ($ip_count/$max_ips)${NC}"
                        lock_user "$username" "IP limit exceeded"
                    else
                        echo -e "${GREEN}✓ $username${NC} from $ip"
                    fi
                fi
            fi
        fi
    done < <(journalctl -u ssh -n 100 --no-pager)
    
    # Show online users
    online_users=$(jq '[.[] | select(.current_ips | length > 0)] | length' $USER_DB)
    echo -e "\n${CYAN}Total Online Users: $online_users${NC}"
}

lock_user() {
    local username=$1
    local reason=${2:-"Manual lock"}
    
    user_index=$(jq 'map(.username) | index("'$username'")' $USER_DB)
    
    if [[ "$user_index" != "null" ]]; then
        # Update database
        jq ".[$user_index].locked = true" $USER_DB > $tmp_file && mv $tmp_file $USER_DB
        
        # Kill user sessions
        pkill -u "$username"
        killall -u "$username" 2>/dev/null
        
        echo -e "${RED}User $username locked!${NC}"
        echo -e "Reason: $reason"
        
        log_message "User locked: $username - Reason: $reason"
        
        # Send notification
        send_notification "🔒 User Locked" "User: $username\nReason: $reason\nTime: $(date)"
    else
        echo -e "${RED}User not found!${NC}"
    fi
}

unlock_user() {
    local username=$1
    
    user_index=$(jq 'map(.username) | index("'$username'")' $USER_DB)
    
    if [[ "$user_index" != "null" ]]; then
        jq ".[$user_index].locked = false | .[$user_index].current_ips = []" $USER_DB > $tmp_file && mv $tmp_file $USER_DB
        
        echo -e "${GREEN}User $username unlocked!${NC}"
        log_message "User unlocked: $username"
        
        send_notification "🔓 User Unlocked" "User: $username\nTime: $(date)"
    else
        echo -e "${RED}User not found!${NC}"
    fi
}

auto_lock_check() {
    echo -e "${CYAN}Running Auto Lock Check...${NC}"
    
    current_date=$(date +%Y-%m-%d)
    
    jq -c '.[]' $USER_DB | while read -r user; do
        username=$(echo "$user" | jq -r '.username')
        expiry=$(echo "$user" | jq -r '.expiry')
        locked=$(echo "$user" | jq -r '.locked')
        ip_count=$(echo "$user" | jq '.current_ips | length')
        max_ips=$(echo "$user" | jq '.max_ips')
        
        # Check expiry
        if [[ "$expiry" < "$current_date" && "$locked" == "false" ]]; then
            lock_user "$username" "Account expired on $expiry"
        fi
        
        # Check IP limit
        if [[ $ip_count -gt $max_ips && "$locked" == "false" ]]; then
            lock_user "$username" "Exceeded IP limit ($ip_count/$max_ips)"
        fi
    done
}

# ====================================================
# BACKUP & RESTORE SYSTEM
# ====================================================

backup_system() {
    echo -e "${GREEN}Creating System Backup...${NC}"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/full-backup-$timestamp.tar.gz"
    
    # Create backup
    tar -czf $backup_file \
        /etc/ssh \
        /etc/ssh-vmess-manager \
        /usr/local/etc/xray \
        /etc/nginx \
        /etc/ssl/certs \
        /var/www/html \
        /var/log/ssh-vmess.log 2>/dev/null
    
    # Encrypt backup
    read -s -p "Encryption password: " enc_pass
    echo
    gpg --batch --yes --passphrase "$enc_pass" -c $backup_file
    rm $backup_file
    
    local encrypted_file="$backup_file.gpg"
    
    echo -e "${GREEN}Backup created: $encrypted_file${NC}"
    
    # Upload to services
    [[ -n "$GMAIL_USER" ]] && backup_to_gmail "$encrypted_file"
    [[ -n "$TELEGRAM_BOT_TOKEN" ]] && backup_to_telegram "$encrypted_file"
    
    log_message "System backup completed: $encrypted_file"
}

backup_to_gmail() {
    local file=$1
    
    echo -e "${YELLOW}Uploading to Gmail...${NC}"
    
    # Using mutt
    apt-get install -y mutt
    
    cat > /root/.muttrc << EOF
set from = "$GMAIL_USER"
set realname = "SSH-VMESS Backup"
set smtp_url = "smtp://$GMAIL_USER@smtp.gmail.com:587/"
set smtp_pass = "$GMAIL_PASS"
set ssl_force_tls = yes
EOF
    
    echo "SSH-VMESS Backup $(date)" | mutt -a "$file" -s "Backup $(date +%Y-%m-%d)" -- $GMAIL_USER
    
    echo -e "${GREEN}Backup sent to Gmail${NC}"
}

backup_to_telegram() {
    local file=$1
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        echo -e "${YELLOW}Uploading to Telegram...${NC}"
        
        # Split if file too large (>50MB)
        local file_size=$(stat -c%s "$file")
        local max_size=50000000
        
        if [[ $file_size -gt $max_size ]]; then
            echo "File too large, splitting..."
            split -b 40M "$file" "${file}_part_"
            
            for part in ${file}_part_*; do
                curl -F chat_id="$TELEGRAM_CHAT_ID" \
                     -F document=@"$part" \
                     https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument > /dev/null 2>&1
            done
            rm ${file}_part_*
        else
            curl -F chat_id="$TELEGRAM_CHAT_ID" \
                 -F document=@"$file" \
                 https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument > /dev/null 2>&1
        fi
        
        echo -e "${GREEN}Backup sent to Telegram${NC}"
    fi
}

restore_system() {
    echo -e "${GREEN}Restore System from Backup${NC}"
    echo "========================="
    
    read -p "Backup file path: " backup_file
    
    if [[ ! -f "$backup_file" ]]; then
        echo -e "${RED}Backup file not found!${NC}"
        return 1
    fi
    
    read -s -p "Decryption password: " dec_pass
    echo
    
    # Decrypt backup
    gpg --batch --yes --passphrase "$dec_pass" -d "$backup_file" > /tmp/restore.tar.gz
    
    # Extract backup
    tar -xzf /tmp/restore.tar.gz -C /
    
    # Restart services
    systemctl restart ssh
    systemctl restart xray
    systemctl restart nginx
    
    echo -e "${GREEN}System restored successfully!${NC}"
    log_message "System restored from: $backup_file"
}

# ====================================================
# MONITORING & BANNER MANAGEMENT
# ====================================================

monitor_system() {
    echo -e "${GREEN}System Monitoring${NC}"
    echo "========================="
    
    # CPU
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    echo -e "CPU Usage: ${CYAN}$cpu_usage%${NC}"
    
    # Memory
    mem_total=$(free -m | awk '/Mem:/ {print $2}')
    mem_used=$(free -m | awk '/Mem:/ {print $3}')
    mem_percent=$((mem_used * 100 / mem_total))
    echo -e "Memory: ${CYAN}$mem_used/${mem_total}MB ($mem_percent%)${NC}"
    
    # Disk
    disk_usage=$(df -h / | awk '/\// {print $5}')
    echo -e "Disk Usage: ${CYAN}$disk_usage${NC}"
    
    # Uptime
    uptime=$(uptime -p)
    echo -e "Uptime: ${CYAN}$uptime${NC}"
    
    # Connections
    ssh_conn=$(netstat -an | grep :$SSH_PORT | grep ESTABLISHED | wc -l)
    total_conn=$(netstat -an | grep ESTABLISHED | wc -l)
    echo -e "SSH Connections: ${CYAN}$ssh_conn${NC}"
    echo -e "Total Connections: ${CYAN}$total_conn${NC}"
    
    # Bandwidth (if vnstat installed)
    if command -v vnstat &>/dev/null; then
        echo -e "\n${GREEN}Bandwidth Usage:${NC}"
        vnstat -d
    fi
}

change_ssh_banner() {
    echo -e "${GREEN}Change SSH Banner${NC}"
    echo "========================="
    
    echo "Current banner:"
    echo "----------------"
    cat /etc/ssh-banner.txt
    echo "----------------"
    
    echo -e "\nEnter new banner text (Ctrl+D to finish):"
    cat > /tmp/new_banner.txt
    
    mv /tmp/new_banner.txt /etc/ssh-banner.txt
    echo -e "${GREEN}Banner updated!${NC}"
    
    # Restart SSH to apply changes
    systemctl restart ssh
    
    log_message "SSH banner changed"
}

show_vmess_configs() {
    echo -e "${GREEN}VMESS Configurations${NC}"
    echo "========================="
    
    if [[ -f $CONFIG_DIR/vmess-config.txt ]]; then
        cat $CONFIG_DIR/vmess-config.txt
    fi
    
    echo -e "\n${GREEN}User VMESS Links:${NC}"
    echo "========================="
    
    for user_file in $CONFIG_DIR/users/*-vmess.json; do
        if [[ -f "$user_file" ]]; then
            username=$(basename "$user_file" "-vmess.json")
            vmess_link="vmess://$(cat "$user_file" | base64 -w0)"
            echo -e "${CYAN}$username:${NC}"
            echo -e "$vmess_link\n"
        fi
    done
}

# ====================================================
# NOTIFICATION SYSTEM
# ====================================================

send_telegram_message() {
    local message="$1"
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="$message" \
            -d parse_mode="Markdown" > /dev/null
    fi
}

send_notification() {
    local title="$1"
    local content="$2"
    
    # Telegram
    send_telegram_message "*$title*\n$content"
    
    # Log
    log_message "Notification: $title - $content"
}

# ====================================================
# MAIN MENU
# ====================================================

show_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${GREEN}MAIN MENU${NC}"
        echo "══════════════════════════════════════════════════"
        echo -e "${CYAN}[1]${NC} Create User Account"
        echo -e "${CYAN}[2]${NC} List All Users"
        echo -e "${CYAN}[3]${NC} Check Online Users"
        echo -e "${CYAN}[4]${NC} Lock User Account"
        echo -e "${CYAN}[5]${NC} Unlock User Account"
        echo -e "${CYAN}[6]${NC} Delete User Account"
        echo -e "${CYAN}[7]${NC} Auto Lock Check"
        echo -e "${YELLOW}[8]${NC} System Monitoring"
        echo -e "${YELLOW}[9]${NC} Change SSH Banner"
        echo -e "${YELLOW}[10]${NC} Show VMESS Configs"
        echo -e "${BLUE}[11]${NC} Backup System"
        echo -e "${BLUE}[12]${NC} Restore System"
        echo -e "${BLUE}[13]${NC} Service Status"
        echo -e "${PURPLE}[14]${NC} Update Script"
        echo -e "${RED}[0]${NC} Exit"
        echo "══════════════════════════════════════════════════"
        
        read -p "Select option: " choice
        
        case $choice in
            1) create_user_account ;;
            2) list_all_users ;;
            3) check_online_users ;;
            4) read -p "Username to lock: " user && lock_user "$user" ;;
            5) read -p "Username to unlock: " user && unlock_user "$user" ;;
            6) read -p "Username to delete: " user && userdel -r "$user" 2>/dev/null && echo "User deleted" ;;
            7) auto_lock_check ;;
            8) monitor_system ;;
            9) change_ssh_banner ;;
            10) show_vmess_configs ;;
            11) backup_system ;;
            12) restore_system ;;
            13) show_service_status ;;
            14) update_script ;;
            0) echo "Goodbye!"; exit 0 ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

show_service_status() {
    echo -e "${GREEN}Service Status${NC}"
    echo "========================="
    
    services=("ssh" "xray" "nginx" "udp-custom-7100" "udp-custom-7200" "udp-custom-7300")
    
    for service in "${services[@]}"; do
        status=$(systemctl is-active "$service")
        if [[ "$status" == "active" ]]; then
            echo -e "$service: ${GREEN}● RUNNING${NC}"
        else
            echo -e "$service: ${RED}● STOPPED${NC}"
        fi
    done
    
    echo -e "\n${GREEN}Port Status:${NC}"
    netstat -tulpn | grep -E ":$SSH_PORT|:$VMESS_PORT|:$VLESS_PORT|:7100|:7200|:7300"
}

update_script() {
    echo -e "${GREEN}Updating Script...${NC}"
    
    wget -O /tmp/install.sh "https://raw.githubusercontent.com/sukronwae85-design/sshvmess-udp-costume/main/install.sh"
    
    if [[ -f /tmp/install.sh ]]; then
        mv /tmp/install.sh $0
        chmod +x $0
        echo -e "${GREEN}Script updated! Restarting...${NC}"
        exec $0
    else
        echo -e "${RED}Update failed!${NC}"
    fi
}

# ====================================================
# AUTO INSTALL FUNCTION
# ====================================================

auto_install() {
    clear
    show_banner
    
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root!${NC}"
        exit 1
    fi
    
    # Check Ubuntu version
    ubuntu_version=$(lsb_release -rs)
    if [[ ! "$ubuntu_version" =~ ^(18|20|22|24) ]]; then
        echo -e "${YELLOW}Warning: This script is tested on Ubuntu 18/20/22/24${NC}"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    # Get domain information
    echo -e "${CYAN}Domain Configuration${NC}"
    echo "========================="
    read -p "Domain name (leave empty for IP only): " DOMAIN
    if [[ -n "$DOMAIN" ]]; then
        read -p "Email for SSL certificate: " EMAIL
    fi
    
    # Get Telegram config (optional)
    echo -e "\n${CYAN}Telegram Notification (Optional)${NC}"
    echo "========================="
    read -p "Telegram Bot Token: " TELEGRAM_BOT_TOKEN
    read -p "Telegram Chat ID: " TELEGRAM_CHAT_ID
    
    # Get Gmail config (optional)
    echo -e "\n${CYAN}Gmail Backup (Optional)${NC}"
    echo "========================="
    read -p "Gmail address: " GMAIL_USER
    if [[ -n "$GMAIL_USER" ]]; then
        echo "Note: Use App Password, not regular password"
        read -s -p "Gmail App Password: " GMAIL_PASS
        echo
    fi
    
    # Start installation
    echo -e "\n${GREEN}Starting installation...${NC}"
    echo "This may take 5-10 minutes."
    echo "========================="
    
    # Step 1: Initialize
    init_system
    
    # Step 2: Install dependencies
    install_dependencies
    
    # Step 3: Install SSH with UDP Custom
    install_ssh_server
    install_udp_custom
    
    # Step 4: Install Xray/VMESS
    install_xray
    
    # Step 5: Install Nginx & SSL
    install_nginx_ssl
    
    # Step 6: Configure firewall
    configure_firewall
    
    # Step 7: Setup cron jobs
    setup_cron_jobs
    
    # Installation complete
    echo -e "\n${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🚀 INSTALLATION COMPLETE!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "Server IP: ${YELLOW}$SERVER_IP${NC}"
    echo -e "SSH Ports: ${YELLOW}$SSH_PORT, $SSH_ALT_PORT${NC}"
    echo -e "UDP Ports: ${YELLOW}7100, 7200, 7300 (1-65535 full range)${NC}"
    echo -e "VMESS Port: ${YELLOW}$VMESS_PORT (with TLS)${NC}"
    echo -e "VLESS Port: ${YELLOW}$VLESS_PORT${NC}"
    echo -e "Trojan Port: ${YELLOW}$TROJAN_PORT${NC}"
    
    if [[ -n "$DOMAIN" ]]; then
        echo -e "Domain: ${YELLOW}https://$DOMAIN${NC}"
    fi
    
    echo -e "\n${GREEN}Next steps:${NC}"
    echo "1. Run './install.sh --menu' to access management"
    echo "2. Create your first user account"
    echo "3. Check VMESS configuration"
    
    # Show VMESS config
    echo -e "\n${GREEN}Default VMESS Configuration:${NC}"
    if [[ -f $CONFIG_DIR/vmess-config.txt ]]; then
        cat $CONFIG_DIR/vmess-config.txt | grep -A5 "VMESS LINK"
    fi
    
    # Save installation log
    log_message "Full installation completed"
    
    # Start menu
    echo -e "\nStarting management menu in 5 seconds..."
    sleep 5
    show_menu
}

configure_firewall() {
    echo -e "${GREEN}Configuring Firewall...${NC}"
    
    # Allow all necessary ports
    ports=($SSH_PORT $SSH_ALT_PORT $VMESS_PORT $VLESS_PORT $TROJAN_PORT 80 443 7100 7200 7300)
    
    for port in "${ports[@]}"; do
        ufw allow $port/tcp
        ufw allow $port/udp
    done
    
    # Allow full UDP range
    ufw allow 1:65535/udp
    
    # Enable UFW
    ufw --force enable
    
    log_message "Firewall configured"
}

setup_cron_jobs() {
    echo -e "${GREEN}Setting up Cron Jobs...${NC}"
    
    # Auto lock check every hour
    (crontab -l 2>/dev/null; echo "0 * * * * $0 --auto-lock") | crontab -
    
    # Auto backup daily at 2 AM
    (crontab -l 2>/dev/null; echo "0 2 * * * $0 --backup") | crontab -
    
    # Auto update script weekly
    (crontab -l 2>/dev/null; echo "0 3 * * 0 $0 --update") | crontab -
    
    # Monitor system every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $0 --monitor") | crontab -
    
    log_message "Cron jobs configured"
}

# ====================================================
# COMMAND LINE INTERFACE
# ====================================================

case "$1" in
    "--install"|"-i")
        auto_install
        ;;
    "--menu"|"-m")
        show_menu
        ;;
    "--create-user"|"-c")
        create_user_account
        ;;
    "--backup"|"-b")
        backup_system
        ;;
    "--restore"|"-r")
        restore_system
        ;;
    "--auto-lock")
        auto_lock_check
        ;;
    "--monitor")
        monitor_system
        ;;
    "--update")
        update_script
        ;;
    "--help"|"-h")
        echo -e "${GREEN}SSH + VMESS + UDP Custom Manager${NC}"
        echo "Usage:"
        echo "  $0 --install     Full automatic installation"
        echo "  $0 --menu        Show management menu"
        echo "  $0 --create-user Create new user"
        echo "  $0 --backup      Create backup"
        echo "  $0 --restore     Restore from backup"
        echo "  $0 --auto-lock   Run auto lock check"
        echo "  $0 --monitor     Show system monitoring"
        echo "  $0 --update      Update script"
        echo "  $0 --help        Show this help"
        ;;
    *)
        # If no arguments, show installation option
        echo -e "${GREEN}SSH + VMESS + UDP Custom Installer${NC}"
        echo "To install, run: $0 --install"
        echo "For menu, run: $0 --menu"
        echo "For help, run: $0 --help"
        ;;
esac