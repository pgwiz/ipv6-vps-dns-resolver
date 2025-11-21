#!/bin/bash

# Cloudflare + Nginx Domain Manager
# Supports IPv4 and IPv6, Multiple Domains
# Usage: sudo ./domain-manager.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Get server IPs
get_server_ips() {
    IPV4_ADDR=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d'/' -f1 | head -n1)
    IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1 | head -n1)
}

# Install dependencies
install_dependencies() {
    echo -e "${GREEN}Installing dependencies...${NC}"
    apt-get update
    apt-get install -y nginx openssl
    
    # Generate snakeoil cert if missing
    if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
        echo -e "${YELLOW}Generating default SSL certificate...${NC}"
        mkdir -p /etc/ssl/private /etc/ssl/certs
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
            -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
        chmod 644 /etc/ssl/certs/ssl-cert-snakeoil.pem
        echo -e "${GREEN}✓ Default SSL certificate created${NC}"
    fi
    
    systemctl enable nginx
    echo -e "${GREEN}Dependencies installed!${NC}\n"
}

# Create Cloudflare IP list for real_ip
create_cf_ips_config() {
    cat > /etc/nginx/conf.d/cloudflare-ips.conf <<'EOF'
# Cloudflare IPv4
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# Cloudflare IPv6
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2c0f:f248::/32;
set_real_ip_from 2a06:98c0::/29;

real_ip_header CF-Connecting-IP;
EOF
}

# Add new domain
add_domain() {
    echo -e "\n${BLUE}=== Add New Domain ===${NC}\n"
    
    read -p "Enter domain name (e.g., example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Domain cannot be empty${NC}"
        return
    fi
    
    if [ -f /etc/nginx/sites-available/$DOMAIN ]; then
        echo -e "${RED}Domain $DOMAIN already exists!${NC}"
        return
    fi
    
    read -p "Add www subdomain? (y/n, default: y): " ADD_WWW
    ADD_WWW=${ADD_WWW:-y}
    
    SERVER_NAMES="$DOMAIN"
    if [ "$ADD_WWW" = "y" ] || [ "$ADD_WWW" = "Y" ]; then
        SERVER_NAMES="$DOMAIN www.$DOMAIN"
    fi
    
    echo -e "\n${YELLOW}Creating configuration for: $DOMAIN${NC}"
    
    # Create Nginx config with both IPv4 and IPv6 support
    cat > /etc/nginx/sites-available/$DOMAIN <<EOF
# HTTP Server - Redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAMES;
    
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $SERVER_NAMES;
    
    root /var/www/$DOMAIN;
    index index.html index.htm index.nginx-debian.html;
    
    # SSL Configuration (default cert, replace with Cloudflare Origin Certificate)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # Logs
    access_log /var/log/nginx/${DOMAIN}_access.log;
    error_log /var/log/nginx/${DOMAIN}_error.log;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP support (uncomment if needed)
    # location ~ \.php$ {
    #     include snippets/fastcgi-php.conf;
    #     fastcgi_pass unix:/var/run/php/php-fpm.sock;
    # }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
    
    # Create web root
    mkdir -p /var/www/$DOMAIN
    
    # Create sample page
    cat > /var/www/$DOMAIN/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to $DOMAIN</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .success {
            color: #28a745;
            font-size: 3em;
            margin-bottom: 10px;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
        }
        .info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #667eea;
        }
        .info-row {
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .label {
            font-weight: bold;
            color: #555;
        }
        .value {
            color: #667eea;
            font-family: monospace;
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 4px;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            background: #28a745;
            color: white;
            border-radius: 15px;
            font-size: 0.85em;
            margin: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success">✓</div>
        <h1>Welcome to $DOMAIN</h1>
        
        <div class="info">
            <div class="info-row">
                <span class="label">Domain:</span>
                <span class="value">$DOMAIN</span>
            </div>
            <div class="info-row">
                <span class="label">Server IPv4:</span>
                <span class="value">${IPV4_ADDR:-Not Available}</span>
            </div>
            <div class="info-row">
                <span class="label">Server IPv6:</span>
                <span class="value">${IPV6_ADDR:-Not Available}</span>
            </div>
            <div class="info-row">
                <span class="label">Web Server:</span>
                <span class="value">Nginx</span>
            </div>
            <div class="info-row">
                <span class="label">Proxy:</span>
                <span class="value">Cloudflare</span>
            </div>
        </div>
        
        <p><strong>Status:</strong> 
            <span class="badge">Server Running</span>
            <span class="badge">SSL Enabled</span>
            <span class="badge">IPv4 + IPv6 Ready</span>
        </p>
        
        <p>Your server is now accessible through Cloudflare's global network!</p>
    </div>
</body>
</html>
EOF
    
    chown -R www-data:www-data /var/www/$DOMAIN
    chmod -R 755 /var/www/$DOMAIN
    
    # Test and reload
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        echo -e "\n${GREEN}✓ Domain $DOMAIN added successfully!${NC}"
        echo -e "\n${YELLOW}Next Steps:${NC}"
        echo -e "1. In Cloudflare, add DNS records:"
        [ -n "$IPV4_ADDR" ] && echo -e "   ${GREEN}A${NC} record: $DOMAIN → $IPV4_ADDR"
        [ -n "$IPV6_ADDR" ] && echo -e "   ${GREEN}AAAA${NC} record: $DOMAIN → $IPV6_ADDR"
        [ "$ADD_WWW" = "y" ] && [ -n "$IPV4_ADDR" ] && echo -e "   ${GREEN}A${NC} record: www.$DOMAIN → $IPV4_ADDR"
        [ "$ADD_WWW" = "y" ] && [ -n "$IPV6_ADDR" ] && echo -e "   ${GREEN}AAAA${NC} record: www.$DOMAIN → $IPV6_ADDR"
        echo -e "2. Enable Cloudflare Proxy (orange cloud icon)"
        echo -e "3. Set SSL/TLS mode to 'Full' or 'Full (Strict)'"
        echo -e "4. Optional: Install Cloudflare Origin Certificate (use option 3 in menu)"
        echo -e "\n${GREEN}Web root:${NC} /var/www/$DOMAIN"
        echo -e "${GREEN}Config:${NC} /etc/nginx/sites-available/$DOMAIN\n"
    else
        echo -e "${RED}Configuration test failed!${NC}"
        rm -f /etc/nginx/sites-enabled/$DOMAIN
    fi
}

# Remove domain
remove_domain() {
    echo -e "\n${BLUE}=== Remove Domain ===${NC}\n"
    
    # List existing domains
    echo -e "${YELLOW}Configured domains:${NC}"
    domains=($(ls /etc/nginx/sites-available/ | grep -v default))
    
    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${RED}No domains configured${NC}\n"
        return
    fi
    
    for i in "${!domains[@]}"; do
        echo -e "  ${GREEN}$((i+1)).${NC} ${domains[$i]}"
    done
    
    echo ""
    read -p "Enter domain name or number: " INPUT
    
    if [ -z "$INPUT" ]; then
        echo -e "${RED}Input cannot be empty${NC}"
        return
    fi
    
    # Check if input is a number
    if [[ "$INPUT" =~ ^[0-9]+$ ]]; then
        index=$((INPUT-1))
        if [ $index -ge 0 ] && [ $index -lt ${#domains[@]} ]; then
            DOMAIN="${domains[$index]}"
        else
            echo -e "${RED}Invalid number!${NC}"
            return
        fi
    else
        DOMAIN="$INPUT"
    fi
    
    if [ ! -f /etc/nginx/sites-available/$DOMAIN ]; then
        echo -e "${RED}Domain $DOMAIN not found!${NC}"
        return
    fi
    
    read -p "Remove web files at /var/www/$DOMAIN? (y/n): " REMOVE_FILES
    
    # Remove nginx config
    rm -f /etc/nginx/sites-enabled/$DOMAIN
    rm -f /etc/nginx/sites-available/$DOMAIN
    
    # Remove SSL cert if exists
    rm -f /etc/ssl/cloudflare/${DOMAIN}.pem
    rm -f /etc/ssl/cloudflare/${DOMAIN}.key
    
    # Remove web files
    if [ "$REMOVE_FILES" = "y" ] || [ "$REMOVE_FILES" = "Y" ]; then
        rm -rf /var/www/$DOMAIN
        echo -e "${GREEN}✓ Web files removed${NC}"
    fi
    
    # Reload nginx
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        echo -e "${GREEN}✓ Domain $DOMAIN removed successfully!${NC}\n"
    else
        echo -e "${RED}Configuration error after removal!${NC}"
    fi
}

# Install Cloudflare Origin Certificate
install_cf_cert() {
    echo -e "\n${BLUE}=== Install Cloudflare Origin Certificate ===${NC}\n"
    
    # List domains
    domains=($(ls /etc/nginx/sites-available/ | grep -v default))
    
    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${RED}No domains configured${NC}\n"
        return
    fi
    
    echo -e "${YELLOW}Available domains:${NC}"
    for i in "${!domains[@]}"; do
        echo -e "  ${GREEN}$((i+1)).${NC} ${domains[$i]}"
    done
    
    echo ""
    read -p "Enter domain name or number: " INPUT
    
    if [ -z "$INPUT" ]; then
        echo -e "${RED}Input cannot be empty${NC}"
        return
    fi
    
    # Check if input is a number
    if [[ "$INPUT" =~ ^[0-9]+$ ]]; then
        index=$((INPUT-1))
        if [ $index -ge 0 ] && [ $index -lt ${#domains[@]} ]; then
            DOMAIN="${domains[$index]}"
        else
            echo -e "${RED}Invalid number!${NC}"
            return
        fi
    else
        DOMAIN="$INPUT"
    fi
    
    if [ ! -f /etc/nginx/sites-available/$DOMAIN ]; then
        echo -e "${RED}Domain $DOMAIN not found!${NC}"
        return
    fi
    
    echo -e "${GREEN}Selected domain:${NC} $DOMAIN\n"
    
    mkdir -p /etc/ssl/cloudflare
    
    echo -e "${YELLOW}Paste your Cloudflare Origin Certificate (press Ctrl+D when done):${NC}"
    cat > /etc/ssl/cloudflare/${DOMAIN}.pem
    
    echo -e "\n${YELLOW}Paste your Private Key (press Ctrl+D when done):${NC}"
    cat > /etc/ssl/cloudflare/${DOMAIN}.key
    
    chmod 600 /etc/ssl/cloudflare/${DOMAIN}.key
    chmod 644 /etc/ssl/cloudflare/${DOMAIN}.pem
    
    # Update nginx config
    sed -i "s|ssl_certificate .*|ssl_certificate /etc/ssl/cloudflare/${DOMAIN}.pem;|g" /etc/nginx/sites-available/$DOMAIN
    sed -i "s|ssl_certificate_key .*|ssl_certificate_key /etc/ssl/cloudflare/${DOMAIN}.key;|g" /etc/nginx/sites-available/$DOMAIN
    
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        echo -e "\n${GREEN}✓ Cloudflare Origin Certificate installed for $DOMAIN!${NC}\n"
    else
        echo -e "${RED}Certificate installation failed!${NC}"
    fi
}

# List domains
list_domains() {
    echo -e "\n${BLUE}=== Configured Domains ===${NC}\n"
    
    if [ ! "$(ls -A /etc/nginx/sites-available/ 2>/dev/null | grep -v default)" ]; then
        echo -e "${YELLOW}No domains configured yet${NC}\n"
        return
    fi
    
    for domain in /etc/nginx/sites-available/*; do
        domain_name=$(basename "$domain")
        [ "$domain_name" = "default" ] && continue
        
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}Domain:${NC} $domain_name"
        
        if [ -L "/etc/nginx/sites-enabled/$domain_name" ]; then
            echo -e "${GREEN}Status:${NC} ✓ Enabled"
        else
            echo -e "${YELLOW}Status:${NC} ✗ Disabled"
        fi
        
        if [ -f "/etc/ssl/cloudflare/${domain_name}.pem" ]; then
            echo -e "${GREEN}SSL:${NC} ✓ Cloudflare Origin Certificate"
        else
            echo -e "${YELLOW}SSL:${NC} ⚠ Default Certificate"
        fi
        
        if [ -d "/var/www/$domain_name" ]; then
            file_count=$(find /var/www/$domain_name -type f | wc -l)
            echo -e "${GREEN}Files:${NC} $file_count files in /var/www/$domain_name"
        fi
        
        echo ""
    done
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Show server info
show_info() {
    echo -e "\n${BLUE}=== Server Information ===${NC}\n"
    get_server_ips
    
    echo -e "${GREEN}IPv4 Address:${NC} ${IPV4_ADDR:-Not Available}"
    echo -e "${GREEN}IPv6 Address:${NC} ${IPV6_ADDR:-Not Available}"
    echo -e "${GREEN}Nginx Version:${NC} $(nginx -v 2>&1 | cut -d'/' -f2)"
    echo -e "${GREEN}Nginx Status:${NC} $(systemctl is-active nginx)"
    echo -e "${GREEN}Config Test:${NC} $(nginx -t 2>&1 | grep -o 'successful' || echo 'failed')"
    echo ""
}

# Main menu
show_menu() {
    clear
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Cloudflare + Nginx Domain Manager       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"
    
    show_info
    
    echo -e "${YELLOW}Available Actions:${NC}\n"
    echo -e "  ${GREEN}1.${NC} Add New Domain"
    echo -e "  ${GREEN}2.${NC} Remove Domain"
    echo -e "  ${GREEN}3.${NC} Install Cloudflare Origin Certificate"
    echo -e "  ${GREEN}4.${NC} List All Domains"
    echo -e "  ${GREEN}5.${NC} Install/Update Dependencies"
    echo -e "  ${GREEN}6.${NC} Restart Nginx"
    echo -e "  ${GREEN}7.${NC} View Nginx Error Log"
    echo -e "  ${RED}0.${NC} Exit\n"
}

# Main loop
main() {
    get_server_ips
    
    # Check if nginx is installed
    if ! command -v nginx &> /dev/null; then
        echo -e "${YELLOW}Nginx not found. Installing dependencies...${NC}\n"
        install_dependencies
    fi
    
    # Create Cloudflare IPs config
    create_cf_ips_config
    
    while true; do
        show_menu
        read -p "Select an option [0-7]: " choice
        
        case $choice in
            1) add_domain ;;
            2) remove_domain ;;
            3) install_cf_cert ;;
            4) list_domains ;;
            5) install_dependencies ;;
            6) 
                echo -e "\n${YELLOW}Restarting Nginx...${NC}"
                systemctl restart nginx
                echo -e "${GREEN}✓ Nginx restarted${NC}\n"
                ;;
            7)
                echo -e "\n${BLUE}=== Last 30 lines of Nginx Error Log ===${NC}\n"
                tail -30 /var/log/nginx/error.log
                echo ""
                ;;
            0)
                echo -e "\n${GREEN}Goodbye!${NC}\n"
                exit 0
                ;;
            *)
                echo -e "\n${RED}Invalid option!${NC}\n"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Run main
main
