# IP6NS — IPv6 DNS64/NAT64 Toolkit

![IP6NS](https://img.shields.io/badge/IP6NS-Toolkit-blue)
![Installer: auto/manual](https://img.shields.io/badge/Install-Automatic%20%7C%20Manual-yellowgreen)
![Security](https://img.shields.io/badge/Security-Inspect%20Before%20Run-red)

Automatic DNS64/NAT64 configuration for IPv6-only VPS instances (Scaleway, AWS, etc.), so they can reach IPv4-only sites like GitHub — plus a diagnostic menu and a Cloudflare + Nginx domain manager.

This repo contains three scripts:

| Script | Purpose |
|---|---|
| `ipv6.sh` | One-shot DNS64/NAT64 setup. Disables the systemd-resolved stub, writes a static `/etc/resolv.conf` pointed at working DNS64 servers, tests against github.com, and locks the file so nothing overwrites it. |
| `ip6res.sh` | Interactive diagnostic menu — scan current setup, test DNS64/NAT64 translation, find/apply the fastest DNS64 server, view network diagnostics, restore from backup. |
| `adddomain.sh` | Cloudflare + Nginx domain manager — add/remove domains, install Cloudflare Origin or Let's Encrypt certificates, supports IPv4 and IPv6. |

Tips to make commands easy to copy:
- On GitHub, fenced code blocks show a "Copy" button — click it to copy the command to your clipboard.
- Clicking the raw script link opens the script in your browser so you can inspect or download it.

ASCII logo (pasteable)
```
   ____  ____ _  _  ____  _____  ___  _____
  (  _ \(  __)( \/ )(  _ \(  _  )/ __)(  _  )
   )(_) )) _)  \  /  ) _ < )(_)(( (_-. )(_)( 
  (____/(____) (__) (____/(_____) \___/(_____)
```

Quick links
- Repo: https://github.com/pgwiz/ipv6-vps-dns-resolver
- Raw `ipv6.sh` (open in browser): https://pastebin.com/raw/e5jjFagF

Contents
- Quick Start (click-to-copy commands)
- Full Toolkit Install (git clone, all 3 scripts)
- Safety & Verification
- Usage & Troubleshooting
- Contributing & License

---

## Quick Start — DNS64/NAT64 only (one-liner)

If you just need working IPv4-site access on an IPv6-only box, this is all you need. Runs `ipv6.sh` directly, no clone required.

Click-to-copy (single-line; GitHub shows a "Copy" button on the right of the code block):

```bash
sudo bash <(curl -fsSL https://pastebin.com/raw/e5jjFagF)
```

Safer workflow (download, inspect, then run):

```bash
curl -fsSL https://pastebin.com/raw/e5jjFagF -o /tmp/ipv6.sh
less /tmp/ipv6.sh      # inspect the script
sudo bash /tmp/ipv6.sh
```

At the end of the run, `ipv6.sh` will offer to install the full toolkit (`ip6res.sh` + `adddomain.sh`) automatically — press `1` to install, or `0` to exit with just DNS64/NAT64 configured.

Open the raw script in your browser (clickable link): https://pastebin.com/raw/e5jjFagF

---

## Full Toolkit Install (git clone, all 3 scripts)

If you want the diagnostic menu and domain manager as well as DNS64 setup, install everything at once:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/pgwiz/ipv6-vps-dns-resolver/main/install.sh)
```

This will:
1. Download all three scripts to `/opt/ip6ns` via `curl` from `raw.githubusercontent.com`.
2. `chmod +x` all three scripts.
3. Offer a menu to run `ipv6.sh`, `ip6res.sh`, or `adddomain.sh` immediately.

**Note on `git clone` and IPv6-only boxes:** `github.com` itself has no IPv6 (AAAA) record — only `raw.githubusercontent.com` does. That means `git clone https://github.com/...` will fail on a fresh IPv6-only VPS *until* DNS64/NAT64 is already configured. `install.sh` avoids this entirely by using plain `curl` against the raw host instead of `git`, so it works standalone with zero prior setup.

If you have IPv4 (or DNS64 already configured) and prefer git:

```bash
git clone https://github.com/pgwiz/ipv6-vps-dns-resolver.git
cd ipv6-vps-dns-resolver
less ipv6.sh              # inspect before running
chmod +x *.sh
sudo ./ipv6.sh
```

---

## Safety & Verification

Running remote scripts directly is risky. Recommended steps:

1. Download and inspect before running:
   ```bash
   curl -fsSL https://pastebin.com/raw/e5jjFagF -o /tmp/ipv6.sh
   less /tmp/ipv6.sh
   ```

2. Run in a safe environment first (VM, container) to validate behavior before using on a production box.

3. All three scripts are plain, readable bash with no obfuscation — `less` any of them before running.

---

## Usage & Verification

```bash
# Check current DNS servers in use
grep nameserver /etc/resolv.conf

# Test DNS64/NAT64 is actually working (not just configured)
curl -6 -v https://github.com

# Re-run the diagnostic menu at any time
sudo bash /opt/ip6ns/ip6res.sh
```

Troubleshooting:
- If `/etc/resolv.conf` is locked and you need to edit it manually: `sudo chattr -i /etc/resolv.conf`
- If systemd-resolved keeps overriding your DNS servers, check `resolvectl status` — the stub listener must be disabled (`ipv6.sh` does this automatically via `/etc/systemd/resolved.conf.d/disable-stub.conf`).
- Backups of the previous `/etc/resolv.conf` are kept as `/etc/resolv.conf.backup.<timestamp>`.

---

## Uninstall

```bash
# Unlock and restore your original resolv.conf
sudo chattr -i /etc/resolv.conf
sudo cp /etc/resolv.conf.backup.<timestamp> /etc/resolv.conf

# Remove the systemd-resolved stub override
sudo rm -f /etc/systemd/resolved.conf.d/disable-stub.conf
sudo systemctl restart systemd-resolved

# Remove the toolkit files
sudo rm -rf /opt/ip6ns
```

---

## Contributing

- Fork the repo
- Create a branch: `git checkout -b feature/your-change`
- Commit, push, and open a PR with a clear description

---

## License

MIT
