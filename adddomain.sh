#!/bin/bash

## Cloudflare + Nginx Setup Helper
#
# This script provides a simple menu for managing multiple domains on an
# Nginx server behind Cloudflare.  It installs the necessary packages on
# first run, allows you to add as many domains as you like, and remove
# them later.  It also generates a self‑signed certificate for each new
# domain so Nginx can start up immediately.  Both IPv4 and IPv6 are
# supported in the generated configuration.
#
# Usage: sudo ./ipv6_cf_nginx_menu.sh

set -euo pipefail

# Colour definitions for nicer output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

# Detect if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root. Please re‑run with sudo.${NC}"
    exit 1
fi

################################################################################
# Helper functions
################################################################################

# Install prerequisite packages (Nginx and Certbot) if they are not present.
install_prerequisites() {
    echo -e "${GREEN}Checking prerequisites...${NC}"
    # Update package lists
    apt-get update -qq
    # Install nginx if not already installed
    if ! command -v nginx >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing Nginx...${NC}"
        apt-get install -y nginx
    fi
    # Install certbot if not already installed
    if ! command -v certbot >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing Certbot...${NC}"
        apt-get install -y certbot python3-certbot-nginx
    fi
}

# Generate a self‑signed certificate for a domain.  Uses openssl and stores
# the files in /etc/ssl/{certs,private}/.
generate_self_signed_cert() {
    local domain="$1"
    local cert_file="/etc/ssl/certs/${domain}-selfsigned.crt"
    local key_file="/etc/ssl/private/${domain}-selfsigned.key"
    if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
        echo -e "${GREEN}Generating self‑signed certificate for ${domain}...${NC}"
        mkdir -p /etc/ssl/certs /etc/ssl/private
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_file" \
            -out "$cert_file" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=${domain}" >/dev/null 2>&1
        chmod 600 "$key_file"
        chmod 644 "$cert_file"
    fi
}

# Create the Nginx server block for a domain.  Takes three arguments:
#   domain     – the primary domain (e.g. example.com)
#   email      – email used for notifications and certificates (not used in self‑signed)
#   add_www    – 'y' if a www subdomain should also respond
create_nginx_config() {
    local domain="$1"
    local email="$2"  # not used yet, reserved for future enhancements
    local add_www="$3"

    local server_names="$domain"
    if [[ "$add_www" =~ ^[Yy]$ ]]; then
        server_names="$domain www.$domain"
    fi

    local site_available="/etc/nginx/sites-available/${domain}"
    local site_enabled="/etc/nginx/sites-enabled/${domain}"

    # Generate self‑signed certificate for this domain
    generate_self_signed_cert "$domain"

    # Build configuration file with IPv4 and IPv6 listeners.  We start by
    # redirecting HTTP to HTTPS, then define the SSL server.  Cloudflare
    # real IP headers are included and can be customised if needed.
    cat > "$site_available" <<EOF
# Managed by ipv6_cf_nginx_menu.sh

server {
    listen 80;
    listen [::]:80;
    server_name $server_names;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $server_names;

    # Root directory
    root /var/www/$domain;
    index index.html index.htm;

    # Use the self‑signed certificate by default.  You should replace these
    # values with a Cloudflare Origin certificate via the provided helper script.
    ssl_certificate     /etc/ssl/certs/${domain}-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/${domain}-selfsigned.key;

    # Basic SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Cloudflare real IP configuration
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
    access_log /var/log/nginx/${domain}_access.log;
    error_log  /var/log/nginx/${domain}_error.log;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Uncomment to enable PHP processing via PHP-FPM
    #location ~ \.php$ {
    #    include snippets/fastcgi-php.conf;
    #    fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    #}
}
EOF

    # Symlink into sites‑enabled
    ln -sf "$site_available" "$site_enabled"

    # Create the web root directory with default index
    mkdir -p "/var/www/${domain}"
    cat > "/var/www/${domain}/index.html" <<INDEX
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to $domain</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: #28a745; font-size: 2em; margin-bottom: 20px; }
        .info { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="success">✓ Server is running!</div>
    <h1>Welcome to $domain</h1>
    <div class="info">
        <p><strong>IPv4 Address:</strong> $(hostname -I | awk '{for(i=1;i<=NF;i++) if($i~/^[0-9.]+$/) {print $i; break}}')</p>
        <p><strong>IPv6 Address:</strong> $(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1 | head -n1)</p>
        <p><strong>Server:</strong> Nginx</p>
        <p><strong>Proxy:</strong> Cloudflare</p>
    </div>
    <p>Your server is reachable via both IPv4 and IPv6 through Cloudflare.</p>
</body>
</html>
INDEX
    chown -R www-data:www-data "/var/www/${domain}"
}

# Add a new domain by prompting for details and creating its configuration
add_domain() {
    read -rp "Enter your domain name (e.g., example.com): " domain
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Domain cannot be empty.${NC}"
        return
    fi
    read -rp "Enter email for notifications/SSL certificates: " email
    if [[ -z "$email" ]]; then
        echo -e "${RED}Email cannot be empty.${NC}"
        return
    fi
    read -rp "Add www subdomain? (y/n, default: y): " add_www
    add_www=${add_www:-y}

    echo -e "${GREEN}Setting up $domain...${NC}"
    create_nginx_config "$domain" "$email" "$add_www"
    # Validate configuration and reload Nginx
    if nginx -t; then
        systemctl reload nginx
        echo -e "${GREEN}Domain $domain has been configured and Nginx reloaded.${NC}"
    else
        echo -e "${RED}There was an error in the configuration. Please check the syntax.${NC}"
    fi
}

# Remove a domain: remove its config, symlink and web root
remove_domain() {
    read -rp "Enter the domain you want to remove: " domain
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Domain cannot be empty.${NC}"
        return
    fi
    local site_available="/etc/nginx/sites-available/${domain}"
    local site_enabled="/etc/nginx/sites-enabled/${domain}"
    local web_root="/var/www/${domain}"

    if [[ -f "$site_enabled" ]]; then
        rm -f "$site_enabled"
    fi
    if [[ -f "$site_available" ]]; then
        rm -f "$site_available"
    fi
    if [[ -d "$web_root" ]]; then
        rm -rf "$web_root"
    fi
    echo -e "${YELLOW}Removed configuration and web root for $domain.${NC}"
    # Test Nginx configuration and reload
    if nginx -t; then
        systemctl reload nginx
        echo -e "${GREEN}Nginx reloaded successfully after removing $domain.${NC}"
    else
        echo -e "${RED}Nginx configuration is invalid after removal! Please fix manually.${NC}"
    fi
}

# List configured domains (based on files in sites-available)
list_domains() {
    echo -e "${GREEN}Configured domains:${NC}"
    ls -1 /etc/nginx/sites-available 2>/dev/null || echo "(none)"
}

# Display a menu and handle user selection
main_menu() {
    while true; do
        echo -e "\n${YELLOW}===== Cloudflare + Nginx Menu =====${NC}"
        echo "1) Add a new domain"
        echo "2) Remove a domain"
        echo "3) List configured domains"
        echo "4) Exit"
        read -rp "Choose an option [1-4]: " choice
        case "$choice" in
            1) add_domain ;;
            2) remove_domain ;;
            3) list_domains ;;
            4) echo "Goodbye"; break ;;
            *) echo -e "${RED}Invalid choice. Please enter 1-4.${NC}" ;;
        esac
    done
}

################################################################################
# Script execution starts here
################################################################################

echo -e "${GREEN}=== Cloudflare + Nginx Setup Helper ===${NC}"
install_prerequisites

# Disable the default site if it exists (prevent conflicts on port 80/443)
if [[ -e /etc/nginx/sites-enabled/default ]]; then
    mv /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.backup 2>/dev/null || true
fi

main_menu

# Provide a hint for the Cloudflare Origin Certificate helper.  This section
# mirrors the original script by creating a helper script for installing the
# origin certificate after you have obtained one from Cloudflare.  The helper
# updates the SSL paths in the domain's config and reloads Nginx.
cat > /root/install_cloudflare_cert.sh <<'CERTSCRIPT'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Please run as root"; exit 1; fi
DOMAIN=$1
if [[ -z "$DOMAIN" ]]; then
  echo "Usage: ./install_cloudflare_cert.sh yourdomain.com"; exit 1
fi
echo "Paste your Cloudflare Origin Certificate (press Ctrl+D when done):"
mkdir -p /etc/ssl/cloudflare
cat > /etc/ssl/cloudflare/${DOMAIN}.pem
echo -e "\nPaste your Private Key (press Ctrl+D when done):"
cat > /etc/ssl/cloudflare/${DOMAIN}.key
chmod 600 /etc/ssl/cloudflare/${DOMAIN}.key
chmod 644 /etc/ssl/cloudflare/${DOMAIN}.pem
# Update nginx config paths
sed -i "s#ssl_certificate .*#ssl_certificate /etc/ssl/cloudflare/${DOMAIN}.pem;#g" /etc/nginx/sites-available/${DOMAIN}
sed -i "s#ssl_certificate_key .*#ssl_certificate_key /etc/ssl/cloudflare/${DOMAIN}.key;#g" /etc/nginx/sites-available/${DOMAIN}
nginx -t && systemctl reload nginx && echo "Certificate installed successfully!"
CERTSCRIPT
chmod +x /root/install_cloudflare_cert.sh

echo -e "${GREEN}Setup helper and menu have completed.${NC}"
