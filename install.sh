#!/bin/bash

# IP6NS Full Toolkit Installer
# Downloads all three scripts directly from raw.githubusercontent.com
# (which has native IPv6 — unlike github.com itself, so this works on
# a fresh IPv6-only box even before DNS64/NAT64 has been set up):
#   ipv6.sh      - one-shot DNS64/NAT64 setup
#   ip6res.sh    - interactive DNS64/NAT64 diagnostic menu
#   adddomain.sh - Cloudflare + Nginx domain manager
# Usage: sudo bash install.sh
#
# NOTE: deliberately does NOT use `git clone`. github.com itself has
# no AAAA/IPv6 record — only raw.githubusercontent.com (served via
# Fastly) does. A git clone here would fail on an IPv6-only box until
# DNS64 is already configured, defeating the point of a standalone
# installer. Plain curl against the raw host avoids that entirely.

RAW_BASE="https://raw.githubusercontent.com/pgwiz/ipv6-vps-dns-resolver/main"
INSTALL_DIR="/opt/ip6ns"
SCRIPTS=("ipv6.sh" "ip6res.sh" "adddomain.sh")

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

echo -e "${BLUE}====================================${NC}"
echo -e "${BLUE}IP6NS Toolkit Installer${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""

mkdir -p "$INSTALL_DIR"

echo -e "${YELLOW}Downloading scripts to $INSTALL_DIR ...${NC}"
fail=0
for script in "${SCRIPTS[@]}"; do
    echo -n "  $script ... "
    if curl -fsSL --max-time 15 "$RAW_BASE/$script" -o "$INSTALL_DIR/$script"; then
        echo -e "${GREEN}ok${NC}"
    else
        echo -e "${RED}failed${NC}"
        fail=1
    fi
done

if [ "$fail" -eq 1 ]; then
    echo ""
    echo -e "${RED}One or more downloads failed.${NC}"
    echo -e "${YELLOW}If this is a fresh IPv6-only box, this is unlikely to be a DNS64${NC}"
    echo -e "${YELLOW}issue — raw.githubusercontent.com has native IPv6. Check general${NC}"
    echo -e "${YELLOW}network connectivity first: curl -6 -v https://raw.githubusercontent.com${NC}"
    exit 1
fi

chmod +x "$INSTALL_DIR"/*.sh

echo ""
echo -e "${GREEN}✓ Toolkit installed to $INSTALL_DIR${NC}"
echo ""

show_menu() {
    echo -e "${YELLOW}Available scripts:${NC}"
    echo "  1) ipv6.sh      - Quick DNS64/NAT64 setup (one-shot)"
    echo "  2) ip6res.sh    - Interactive DNS64/NAT64 diagnostic menu"
    echo "  3) adddomain.sh - Cloudflare + Nginx domain manager"
    echo "  0) Exit (run scripts later from $INSTALL_DIR)"
    echo ""
    read -p "Run which script now? [0-3]: " choice

    case "$choice" in
        1) bash "$INSTALL_DIR/ipv6.sh" ;;
        2) bash "$INSTALL_DIR/ip6res.sh" ;;
        3) bash "$INSTALL_DIR/adddomain.sh" ;;
        0)
            echo ""
            echo "Done. Scripts are in $INSTALL_DIR — run any of them anytime with:"
            echo "  sudo bash $INSTALL_DIR/ipv6.sh"
            echo "  sudo bash $INSTALL_DIR/ip6res.sh"
            echo "  sudo bash $INSTALL_DIR/adddomain.sh"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            echo ""
            show_menu
            ;;
    esac
}

show_menu
