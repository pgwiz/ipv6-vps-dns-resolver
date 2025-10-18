#!/bin/bash

# Cloudflare + Nginx Setup Script for IPv6-only Server
# Usage: sudo ./setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Cloudflare + Nginx IPv6 Setup ===${NC}\n"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Get domain from user
read -p "Enter your domain name (e.g., example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domain cannot be empty${NC}"
    exit 1
fi

read -p "Enter email for SSL certificate: " EMAIL
if [ -z "$EMAIL" ]; then
    echo -e "${RED}Email cannot be empty${NC}"
    exit 1
fi

# Optional: subdomain support
read -p "Add www subdomain? (y/n, default: y): " ADD_WWW
ADD_WWW=${ADD_WWW:-y}

echo -e "\n${YELLOW}Starting setup for: $DOMAIN${NC}\n"

# Update system
echo -e "${GREEN}[1/7] Updating system...${NC}"
apt-get update
apt-get upgrade -y

# Install Nginx
echo -e "${GREEN}[2/7] Installing Nginx...${NC}"
apt-get install -y nginx

# Install Certbot for Let's Encrypt (optional, since Cloudflare provides SSL)
echo -e "${GREEN}[3/7] Installing Certbot...${NC}"
apt-get install -y certbot python3-certbot-nginx

# Get server's IPv6 address
IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1 | head -n1)
echo -e "${YELLOW}Detected IPv6 address: $IPV6_ADDR${NC}"

# Backup default nginx config
echo -e "${GREEN}[4/7] Backing up default Nginx config...${NC}"
if [ -f /etc/nginx/sites-enabled/default ]; then
    mv /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.backup
fi

# Generate temporary self-signed certificate
echo -e "${GREEN}[5/8] Generating temporary SSL certificate...${NC}"
mkdir -p /etc/ssl/private /etc/ssl/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/$DOMAIN-selfsigned.key \
    -out /etc/ssl/certs/$DOMAIN-selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"

# Create Nginx configuration
echo -e "${GREEN}[6/8] Creating Nginx configuration...${NC}"

SERVER_NAMES="$DOMAIN"
if [ "$ADD_WWW" = "y" ] || [ "$ADD_WWW" = "Y" ]; then
    SERVER_NAMES="$DOMAIN www.$DOMAIN"
fi

cat > /etc/nginx/sites-available/$DOMAIN <<EOF
# HTTP Server Block - IPv6
server {
    listen [::]:80;
    server_name $SERVER_NAMES;
    
    # For Cloudflare SSL (redirect to HTTPS)
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server Block - IPv6
server {
    listen [::]:443 ssl http2;
    server_name $SERVER_NAMES;
    
    # Root directory
    root /var/www/$DOMAIN;
    index index.html index.htm index.nginx-debian.html;
    
    # SSL Configuration (will be updated with Cloudflare Origin Certificate)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Cloudflare Real IP (to get actual visitor IPs)
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2c0f:f248::/32;
    set_real_ip_from 2a06:98c0::/29;
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
    real_ip_header CF-Connecting-IP;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Logs
    access_log /var/log/nginx/${DOMAIN}_access.log;
    error_log /var/log/nginx/${DOMAIN}_error.log;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP support (uncomment if needed)
    # location ~ \.php$ {
    #     include snippets/fastcgi-php.conf;
    #     fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    # }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/

# Create web root directory
echo -e "${GREEN}[6/7] Creating web root directory...${NC}"
mkdir -p /var/www/$DOMAIN
chown -R www-data:www-data /var/www/$DOMAIN
chmod -R 755 /var/www/$DOMAIN

# Create sample index.html
cat > /var/www/$DOMAIN/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to $DOMAIN</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }
        .success {
            color: #28a745;
            font-size: 2em;
            margin-bottom: 20px;
        }
        .info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="success">✓ Server is running!</div>
    <h1>Welcome to $DOMAIN</h1>
    <div class="info">
        <p><strong>IPv6 Address:</strong> $IPV6_ADDR</p>
        <p><strong>Server:</strong> Nginx on Scaleway</p>
        <p><strong>Proxy:</strong> Cloudflare</p>
    </div>
    <p>Your IPv6-only server is now accessible via IPv4 and IPv6 through Cloudflare!</p>
</body>
</html>
EOF

chown www-data:www-data /var/www/$DOMAIN/index.html

# Test Nginx configuration
echo -e "${GREEN}[7/7] Testing Nginx configuration...${NC}"
nginx -t

# Restart Nginx
echo -e "${GREEN}Restarting Nginx...${NC}"
systemctl restart nginx
systemctl enable nginx

# Configure firewall (if UFW is installed)
if command -v ufw &> /dev/null; then
    echo -e "${YELLOW}Configuring firewall...${NC}"
    ufw allow 'Nginx Full'
    ufw --force enable
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "1. Add your domain to Cloudflare"
echo -e "2. Create an AAAA record pointing to: ${GREEN}$IPV6_ADDR${NC}"
echo -e "3. Enable Cloudflare Proxy (orange cloud)"
echo -e "4. Set SSL/TLS mode to 'Full' in Cloudflare dashboard"
echo -e "\n${YELLOW}Optional: Install Cloudflare Origin Certificate${NC}"
echo -e "5. Go to SSL/TLS > Origin Server in Cloudflare"
echo -e "6. Create Certificate and download it"
echo -e "7. Save certificate to: /etc/ssl/cloudflare/${DOMAIN}.pem"
echo -e "8. Save private key to: /etc/ssl/cloudflare/${DOMAIN}.key"
echo -e "9. Update nginx config at: /etc/nginx/sites-available/$DOMAIN"
echo -e "\n${GREEN}Your site will be available at: https://$DOMAIN${NC}"
echo -e "\n${YELLOW}Server IPv6: $IPV6_ADDR${NC}"
echo -e "${YELLOW}Web root: /var/www/$DOMAIN${NC}"
echo -e "${YELLOW}Nginx config: /etc/nginx/sites-available/$DOMAIN${NC}"
echo -e "${YELLOW}Logs: /var/log/nginx/${DOMAIN}_*.log${NC}\n"

# Display Cloudflare Origin Certificate installation helper
cat > /root/install_cloudflare_cert.sh <<'CERTSCRIPT'
#!/bin/bash
# Helper script to install Cloudflare Origin Certificate

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./install_cloudflare_cert.sh yourdomain.com"
    exit 1
fi

echo "Paste your Cloudflare Origin Certificate (press Ctrl+D when done):"
mkdir -p /etc/ssl/cloudflare
cat > /etc/ssl/cloudflare/${DOMAIN}.pem

echo -e "\nPaste your Private Key (press Ctrl+D when done):"
cat > /etc/ssl/cloudflare/${DOMAIN}.key

chmod 600 /etc/ssl/cloudflare/${DOMAIN}.key
chmod 644 /etc/ssl/cloudflare/${DOMAIN}.pem

# Update nginx config
sed -i "s|ssl_certificate .*|ssl_certificate /etc/ssl/cloudflare/${DOMAIN}.pem;|g" /etc/nginx/sites-available/$DOMAIN
sed -i "s|ssl_certificate_key .*|ssl_certificate_key /etc/ssl/cloudflare/${DOMAIN}.key;|g" /etc/nginx/sites-available/$DOMAIN

nginx -t && systemctl reload nginx

echo "Certificate installed successfully!"
CERTSCRIPT

chmod +x /root/install_cloudflare_cert.sh

echo -e "${GREEN}Certificate helper script created: /root/install_cloudflare_cert.sh${NC}"
echo -e "Run: ${YELLOW}sudo /root/install_cloudflare_cert.sh $DOMAIN${NC} to install Cloudflare Origin Certificate\n"