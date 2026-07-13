#!/bin/bash
# Advanced IPv6 DNS64/NAT64 Setup and Diagnostic Script
# Configures DNS for IPv6-only servers with NAT64 translation
# Version: 2.1 (fixed)
# Usage: sudo bash setup-ipv6-dns-advanced.sh

# NOTE: removed `set -e` — a diagnostic/menu tool should not die on the
# first failed grep/dig/ping. Each function handles its own errors instead.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# DNS64 servers with NAT64 support
declare -A DNS64_SERVERS=(
    ["Hetzner"]="2a01:4f8:c2c:123f::1"
    ["Cloudflare"]="2606:4700:4700::64"
    ["Google"]="2001:4860:4860::6464"
    ["UltraTools"]="2a00:1098:2b::1"
    ["Mythic"]="2a01:4f9:c010:3f02::1"
)

# Known IPv4-only test domains
IPV4_TEST_DOMAINS=("github.com" "sourceforge.net" "bitbucket.org")

# ---------- Helper functions ----------
# IMPORTANT: these print to stdout normally, but any function whose
# output gets captured with $(...) must redirect these to stderr (>&2)
# so status text doesn't get mixed into the captured value.

print_header() {
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo ""
}

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error()   { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info()    { echo -e "${BLUE}ℹ️  $1${NC}"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script needs root privileges."
        echo "Please run with: sudo bash $0"
        exit 1
    fi
}

# Detect if system is IPv6-only
detect_ipv6_only() {
    print_info "Detecting network configuration..."

    local has_ipv4=false
    local has_ipv6=false

    if ip -4 addr | grep -q "inet " && ! ip -4 addr | grep -qE "inet 127\."; then
        has_ipv4=true
    fi

    if ip -6 addr | grep -q "inet6 " && ! ip -6 addr | grep -q "inet6 ::1"; then
        has_ipv6=true
    fi

    echo ""
    if $has_ipv4 && $has_ipv6; then
        print_info "Dual-stack network detected (IPv4 + IPv6)"
        return 2
    elif ! $has_ipv4 && $has_ipv6; then
        print_warning "IPv6-only network detected"
        print_info "You need DNS64/NAT64 to access IPv4-only sites"
        return 0
    elif $has_ipv4 && ! $has_ipv6; then
        print_info "IPv4-only network detected"
        return 1
    else
        print_error "No network connectivity detected"
        return 3
    fi
}

# Check current DNS configuration
check_current_dns() {
    print_header "Current DNS Configuration"

    if [ -f /etc/resolv.conf ]; then
        echo "📄 /etc/resolv.conf contents:"
        grep -v "^#" /etc/resolv.conf | grep -v "^$"
        echo ""
    else
        print_warning "/etc/resolv.conf not found"
    fi

    if [ -L /etc/resolv.conf ]; then
        print_info "/etc/resolv.conf is a symlink to: $(readlink -f /etc/resolv.conf)"
    fi

    # This is the thing that actually matters: is the stub listener active?
    # If it is, writes to /etc/resolv.conf can be bypassed at query time.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if resolvectl status 2>/dev/null | grep -q "resolv.conf mode: stub"; then
            print_warning "systemd-resolved stub is ACTIVE — it may override your DNS64 config"
            print_info "Run option 4 or 5 to disable the stub properly"
        fi
    fi
    echo ""
}

# Test DNS64 functionality — queries the DNS64 servers DIRECTLY,
# not the system default resolver (which may not be doing synthesis)
test_dns64() {
    print_header "Testing DNS64/NAT64 Translation"

    local test_passed=0
    local test_failed=0

    print_info "Querying DNS64 servers directly for IPv4-only domains..."
    echo ""

    for domain in "${IPV4_TEST_DOMAINS[@]}"; do
        local resolved=false
        for name in "${!DNS64_SERVERS[@]}"; do
            local server="${DNS64_SERVERS[$name]}"
            local ipv6_result
            ipv6_result=$(dig +short +time=2 +tries=1 AAAA "$domain" @"$server" 2>/dev/null | head -n1)

            if [ -n "$ipv6_result" ]; then
                print_success "$domain via $name: synthesized $ipv6_result"
                ((test_passed++))
                resolved=true
                break
            fi
        done
        if ! $resolved; then
            print_error "$domain: no DNS64 server returned a AAAA record"
            ((test_failed++))
        fi
    done

    echo ""
    if [ $test_failed -eq 0 ]; then
        print_success "DNS64 translation is working!"
        return 0
    else
        print_warning "DNS64 translation issues detected ($test_failed/$((test_passed + test_failed)) failed)"
        return 1
    fi
}

# Test actual connectivity to IPv4-only sites over the CURRENT active resolver.
# Uses curl over HTTPS instead of ping — ping/ICMP is frequently blocked
# even when the DNS64/NAT64 path itself works fine.
test_ipv4_connectivity() {
    print_header "Testing IPv4 Site Connectivity (via active DNS config)"

    print_info "Attempting to reach IPv4-only sites via NAT64 (HTTPS, not ping)..."
    echo ""

    local success=0
    local failed=0

    for domain in "${IPV4_TEST_DOMAINS[@]}"; do
        echo -n "Fetching https://$domain ... "
        local code
        code=$(curl -6 -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$domain" 2>/dev/null)
        if [[ "$code" =~ ^(200|301|302|403)$ ]]; then
            print_success "Reachable (HTTP $code)"
            ((success++))
        else
            print_error "Unreachable (got: '${code:-timeout}')"
            ((failed++))
        fi
    done

    echo ""
    if [ $failed -eq 0 ]; then
        print_success "NAT64 connectivity working!"
        return 0
    else
        print_warning "NAT64 connectivity issues ($failed/$((success + failed)) failed)"
        print_info "If DNS64 test (option 2) passed but this fails, the active"
        print_info "resolver (systemd-resolved stub) is likely not using DNS64."
        return 1
    fi
}

# Test individual DNS64 servers and print the fastest.
# FIX: all diagnostic output goes to stderr (>&2) so that
# `best_server=$(test_dns64_servers)` only captures the final result line.
test_dns64_servers() {
    {
        print_header "Testing Available DNS64 Servers"
        print_info "Finding the best DNS64 server for your network..."
        echo ""
    } >&2

    local best_server=""
    local best_time=9999

    for name in "${!DNS64_SERVERS[@]}"; do
        local server="${DNS64_SERVERS[$name]}"
        echo -n "Testing $name ($server)... " >&2

        local start end time result
        start=$(date +%s%N)
        result=$(dig @"$server" +short +time=2 +tries=1 AAAA github.com 2>/dev/null | head -n1)
        end=$(date +%s%N)
        time=$(((end - start) / 1000000))

        if [ -n "$result" ]; then
            print_success "Working (${time}ms) - $result" >&2
            if [ "$time" -lt "$best_time" ]; then
                best_time=$time
                best_server="$name:$server"
            fi
        else
            print_error "Not responding" >&2
        fi
    done

    echo "" >&2
    if [ -n "$best_server" ]; then
        print_success "Best server: ${best_server%%:*} (${best_time}ms)" >&2
        echo "$best_server"   # ONLY this goes to stdout
    else
        print_error "No working DNS64 servers found" >&2
        return 1
    fi
}

# Apply recommended DNS64 configuration
apply_dns64_config() {
    local server_info="$1"

    print_header "Applying DNS64 Configuration"

    # Unlock in case a previous run locked the file
    chattr -i /etc/resolv.conf 2>/dev/null

    # Disable systemd-resolved's stub listener so it can't silently
    # override queries with a non-DNS64 upstream. This was the root
    # cause of "config applied but github.com still unreachable".
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        print_info "Disabling systemd-resolved stub listener..."
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/dns64-stub-disable.conf <<EOF
[Resolve]
DNSStubListener=no
EOF
        systemctl restart systemd-resolved 2>/dev/null
        print_success "Stub listener disabled"
    fi

    # Backup existing config (dereference symlink so we back up real content)
    if [ -e /etc/resolv.conf ]; then
        local backup="/etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)"
        cp -L /etc/resolv.conf "$backup" 2>/dev/null
        print_success "Backup created: $backup"
    fi

    # Extract best server if provided
    local primary_dns64=""
    if [ -n "$server_info" ]; then
        primary_dns64="${server_info##*:}"
    fi

    # Remove symlink/file, write a real static file directly.
    # NOTE: intentionally NOT mixing in plain (non-DNS64) fallback
    # nameservers here — glibc round-robins between nameserver lines,
    # so a non-synthesizing server in the mix causes intermittent
    # failures for IPv4-only sites even when DNS64 itself works.
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf <<EOF
# IPv6 DNS64/NAT64 Configuration
# Generated by setup-ipv6-dns-advanced.sh on $(date)
# This enables IPv6-only servers to reach IPv4-only sites

${primary_dns64:+nameserver $primary_dns64}
nameserver 2a01:4f8:c2c:123f::1
nameserver 2a00:1098:2b::1
nameserver 2a01:4f9:c010:3f02::1

options edns0 trust-ad
EOF

    print_success "DNS64 configuration applied to /etc/resolv.conf"
    echo ""
    print_success "DNS64 configuration complete!"
}

# Make configuration permanent (lock the file)
make_permanent() {
    print_header "Making Configuration Permanent"

    if [ -L /etc/resolv.conf ]; then
        print_warning "/etc/resolv.conf is currently a symlink"
        read -p "Replace it with a static locked DNS64 config? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            unlink /etc/resolv.conf
            apply_dns64_config ""
        else
            print_info "Skipped."
            return
        fi
    fi

    chattr +i /etc/resolv.conf 2>/dev/null \
        && print_success "Configuration locked (use 'chattr -i /etc/resolv.conf' to unlock)" \
        || print_warning "Could not set immutable flag (filesystem may not support it)"
}

# Display diagnostic information
show_diagnostics() {
    print_header "Network Diagnostics"

    echo "📡 Network Interfaces:"
    ip -br addr show | grep -v "^lo"
    echo ""

    echo "🌐 IPv6 Default Route:"
    ip -6 route | grep default || echo "(none found)"
    echo ""

    echo "📋 Current DNS Servers:"
    grep nameserver /etc/resolv.conf 2>/dev/null || echo "(none found)"
    echo ""

    if command -v resolvectl &> /dev/null; then
        echo "🔍 systemd-resolved status:"
        resolvectl status | head -20
        echo ""
    fi
}

# ---------- Main menu ----------
# FIX: changed from recursive self-call to a while loop, so a long
# interactive session doesn't grow the call stack indefinitely.
show_menu() {
    while true; do
        clear
        print_header "IPv6 DNS64/NAT64 Configuration Tool"

        echo "1) Scan and diagnose current setup"
        echo "2) Test DNS64/NAT64 translation"
        echo "3) Find and apply best DNS64 server"
        echo "4) Apply recommended configuration"
        echo "5) Make configuration permanent"
        echo "6) Show network diagnostics"
        echo "7) Restore from backup"
        echo "0) Exit"
        echo ""
        read -p "Select option: " choice

        case $choice in
            1)
                detect_ipv6_only
                check_current_dns
                test_dns64
                test_ipv4_connectivity
                ;;
            2)
                test_dns64
                test_ipv4_connectivity
                ;;
            3)
                best_server=$(test_dns64_servers)
                echo ""
                read -p "Apply this configuration? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    apply_dns64_config "$best_server"
                    test_ipv4_connectivity
                fi
                ;;
            4)
                apply_dns64_config ""
                test_ipv4_connectivity
                ;;
            5)
                make_permanent
                ;;
            6)
                show_diagnostics
                ;;
            7)
                echo ""
                echo "Available backups:"
                ls -1 /etc/resolv.conf.backup.* 2>/dev/null | tail -5
                echo ""
                read -p "Enter backup filename to restore: " backup
                if [ -f "$backup" ]; then
                    chattr -i /etc/resolv.conf 2>/dev/null
                    cp "$backup" /etc/resolv.conf
                    print_success "Configuration restored from $backup"
                else
                    print_error "Backup file not found"
                fi
                ;;
            0)
                print_info "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# ---------- Main execution ----------
main() {
    check_root

    for cmd in dig curl ip; do
        if ! command -v $cmd &> /dev/null; then
            print_error "$cmd is not installed"
            print_info "Install with: apt-get install dnsutils curl iproute2"
            exit 1
        fi
    done

    show_menu
}

main
print_header() {
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "This script needs root privileges."
        echo "Please run with: sudo bash $0"
        exit 1
    fi
}

# Detect if system is IPv6-only
detect_ipv6_only() {
    print_info "Detecting network configuration..."
    
    local has_ipv4=false
    local has_ipv6=false
    
    if ip -4 addr | grep -q "inet " && ! ip -4 addr | grep -q "inet 127."; then
        has_ipv4=true
    fi
    
    if ip -6 addr | grep -q "inet6 " && ! ip -6 addr | grep -q "inet6 ::1"; then
        has_ipv6=true
    fi
    
    echo ""
    if $has_ipv4 && $has_ipv6; then
        print_info "Dual-stack network detected (IPv4 + IPv6)"
        return 2
    elif ! $has_ipv4 && $has_ipv6; then
        print_warning "IPv6-only network detected"
        print_info "You need DNS64/NAT64 to access IPv4-only sites"
        return 0
    elif $has_ipv4 && ! $has_ipv6; then
        print_info "IPv4-only network detected"
        return 1
    else
        print_error "No network connectivity detected"
        return 3
    fi
}

# Check current DNS configuration
check_current_dns() {
    print_header "Current DNS Configuration"
    
    if [ -f /etc/resolv.conf ]; then
        echo "📄 /etc/resolv.conf contents:"
        cat /etc/resolv.conf | grep -v "^#" | grep -v "^$"
        echo ""
    else
        print_warning "/etc/resolv.conf not found"
    fi
    
    if [ -L /etc/resolv.conf ]; then
        print_info "/etc/resolv.conf is a symlink to: $(readlink -f /etc/resolv.conf)"
    fi
    echo ""
}

# Test DNS64 functionality
test_dns64() {
    print_header "Testing DNS64/NAT64 Translation"
    
    local test_passed=0
    local test_failed=0
    
    print_info "Testing IPv4-only domains (should work with DNS64)..."
    echo ""
    
    for domain in "${IPV4_TEST_DOMAINS[@]}"; do
        echo -n "Testing $domain... "
        
        # Check if domain resolves to IPv6 (DNS64 synthesized)
        local ipv6_result=$(dig +short AAAA "$domain" 2>/dev/null | head -n1)
        
        if [ -n "$ipv6_result" ]; then
            # Check if it's a DNS64 synthesized address (usually starts with 64:ff9b::)
            if [[ "$ipv6_result" =~ ^64:ff9b:: ]] || [[ "$ipv6_result" =~ ^2a ]]; then
                print_success "DNS64 working ($ipv6_result)"
                ((test_passed++))
            else
                print_info "Native IPv6 found ($ipv6_result)"
                ((test_passed++))
            fi
        else
            print_error "No IPv6 address (DNS64 may not be working)"
            ((test_failed++))
        fi
    done
    
    echo ""
    if [ $test_failed -eq 0 ]; then
        print_success "DNS64 translation appears to be working!"
        return 0
    else
        print_warning "DNS64 translation issues detected ($test_failed/$((test_passed + test_failed)) failed)"
        return 1
    fi
}

# Test actual connectivity to IPv4 sites
test_ipv4_connectivity() {
    print_header "Testing IPv4 Site Connectivity"
    
    print_info "Attempting to reach IPv4-only sites via NAT64..."
    echo ""
    
    local success=0
    local failed=0
    
    for domain in "${IPV4_TEST_DOMAINS[@]}"; do
        echo -n "Pinging $domain... "
        if ping -c 2 -W 3 "$domain" > /dev/null 2>&1; then
            print_success "Reachable"
            ((success++))
        else
            print_error "Unreachable"
            ((failed++))
        fi
    done
    
    echo ""
    if [ $failed -eq 0 ]; then
        print_success "NAT64 connectivity working!"
        return 0
    else
        print_warning "NAT64 connectivity issues ($failed/$((success + failed)) failed)"
        return 1
    fi
}

# Test individual DNS64 servers
test_dns64_servers() {
    print_header "Testing Available DNS64 Servers"
    
    print_info "Finding the best DNS64 server for your network..."
    echo ""
    
    local best_server=""
    local best_time=9999
    
    for name in "${!DNS64_SERVERS[@]}"; do
        local server="${DNS64_SERVERS[$name]}"
        echo -n "Testing $name ($server)... "
        
        # Test with dig and measure time
        local start=$(date +%s%N)
        local result=$(dig @"$server" +short AAAA github.com 2>/dev/null | head -n1)
        local end=$(date +%s%N)
        local time=$((($end - $start) / 1000000))
        
        if [ -n "$result" ]; then
            print_success "Working (${time}ms) - $result"
            if [ $time -lt $best_time ]; then
                best_time=$time
                best_server="$name:$server"
            fi
        else
            print_error "Not responding"
        fi
    done
    
    echo ""
    if [ -n "$best_server" ]; then
        print_success "Best server: ${best_server%%:*} (${best_time}ms)"
        echo "$best_server"
    else
        print_error "No working DNS64 servers found"
        return 1
    fi
}

# Apply recommended DNS64 configuration
apply_dns64_config() {
    local server_info="$1"
    
    print_header "Applying DNS64 Configuration"
    
    # Backup existing config
    if [ -f /etc/resolv.conf ]; then
        local backup="/etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)"
        cp /etc/resolv.conf "$backup"
        print_success "Backup created: $backup"
    fi
    
    # Extract best server if provided
    local primary_dns64=""
    if [ -n "$server_info" ]; then
        primary_dns64="${server_info##*:}"
    fi
    
    # Create new resolv.conf
    cat > /etc/resolv.conf <<EOF
# IPv6 DNS64/NAT64 Configuration
# Generated by setup-ipv6-dns-advanced.sh on $(date)
# This enables IPv6-only servers to reach IPv4-only sites

# Primary DNS64 servers (with NAT64 translation)
${primary_dns64:+nameserver $primary_dns64}
nameserver 2a01:4f8:c2c:123f::1
nameserver 2606:4700:4700::64
nameserver 2a00:1098:2b::1

# Fallback DNS servers
nameserver 2001:4860:4860::8888
nameserver 2001:4860:4860::8844
nameserver 8.8.8.8
nameserver 8.8.4.4

options edns0 trust-ad
EOF
    
    print_success "DNS64 configuration applied to /etc/resolv.conf"
    
    # Configure systemd-resolved if available
    if [ -f /etc/systemd/resolved.conf ]; then
        print_info "Configuring systemd-resolved..."
        cp /etc/systemd/resolved.conf "/etc/systemd/resolved.conf.backup.$(date +%Y%m%d_%H%M%S)"
        
        cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=${primary_dns64:-2a01:4f8:c2c:123f::1} 2001:4860:4860::8888
FallbackDNS=2606:4700:4700::1111 8.8.8.8
DNSOverTLS=no
DNSSEC=allow-downgrade
Cache=yes
EOF
        
        systemctl restart systemd-resolved 2>/dev/null || true
        print_success "systemd-resolved configured and restarted"
    fi
    
    echo ""
    print_success "DNS64 configuration complete!"
}

# Make configuration permanent
make_permanent() {
    print_header "Making Configuration Permanent"
    
    if [ -L /etc/resolv.conf ]; then
        print_warning "/etc/resolv.conf is a symlink"
        print_info "To prevent it from being overwritten, we can:"
        echo "  1. Unlink it and create a static file"
        echo "  2. Configure systemd-resolved to manage it"
        echo ""
        read -p "Make DNS settings permanent? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            local target=$(readlink -f /etc/resolv.conf)
            unlink /etc/resolv.conf
            apply_dns64_config ""
            chattr +i /etc/resolv.conf 2>/dev/null || true
            print_success "Configuration locked (use 'chattr -i /etc/resolv.conf' to unlock)"
        fi
    else
        chattr +i /etc/resolv.conf 2>/dev/null || true
        print_success "Configuration locked against modifications"
    fi
}

# Display diagnostic information
show_diagnostics() {
    print_header "Network Diagnostics"
    
    echo "📡 Network Interfaces:"
    ip -br addr show | grep -v "lo"
    echo ""
    
    echo "🌐 IPv6 Routes:"
    ip -6 route | head -5
    echo ""
    
    echo "📋 Current DNS Servers:"
    cat /etc/resolv.conf | grep nameserver
    echo ""
    
    if command -v resolvectl &> /dev/null; then
        echo "🔍 systemd-resolved status:"
        resolvectl status | head -20
        echo ""
    fi
}

# Main menu
show_menu() {
    clear
    print_header "IPv6 DNS64/NAT64 Configuration Tool"
    
    echo "1) Scan and diagnose current setup"
    echo "2) Test DNS64/NAT64 translation"
    echo "3) Find and apply best DNS64 server"
    echo "4) Apply recommended configuration"
    echo "5) Make configuration permanent"
    echo "6) Show network diagnostics"
    echo "7) Restore from backup"
    echo "0) Exit"
    echo ""
    read -p "Select option: " choice
    
    case $choice in
        1)
            detect_ipv6_only
            check_current_dns
            test_dns64
            test_ipv4_connectivity
            ;;
        2)
            test_dns64
            test_ipv4_connectivity
            ;;
        3)
            best_server=$(test_dns64_servers)
            echo ""
            read -p "Apply this configuration? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                apply_dns64_config "$best_server"
                test_ipv4_connectivity
            fi
            ;;
        4)
            apply_dns64_config ""
            test_ipv4_connectivity
            ;;
        5)
            make_permanent
            ;;
        6)
            show_diagnostics
            ;;
        7)
            echo ""
            echo "Available backups:"
            ls -1 /etc/resolv.conf.backup.* 2>/dev/null | tail -5
            echo ""
            read -p "Enter backup filename to restore: " backup
            if [ -f "$backup" ]; then
                cp "$backup" /etc/resolv.conf
                print_success "Configuration restored from $backup"
            else
                print_error "Backup file not found"
            fi
            ;;
        0)
            print_info "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# Main execution
main() {
    check_root
    
    # Check if script has required tools
    for cmd in dig ping ip; do
        if ! command -v $cmd &> /dev/null; then
            print_error "$cmd is not installed"
            print_info "Install with: apt-get install dnsutils iputils-ping iproute2"
            exit 1
        fi
    done
    
    show_menu
}

main
