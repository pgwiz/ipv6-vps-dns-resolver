# IP6NS Installer

![IP6NS](https://img.shields.io/badge/IP6NS-Installer-blue)
![Installer: auto/manual](https://img.shields.io/badge/Install-Automatic%20%7C%20Manual-yellowgreen)
![Security](https://img.shields.io/badge/Security-Inspect%20Before%20Run-red)

A small installer for the IP6NS script hosted at: https://ip6ns.pgwiz.us.kg

This README shows two installation methods:
- Automatic (one‑liner) using the hosted installer
- Manual via git clone

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
- Raw installer (open in browser): https://ip6ns.pgwiz.us.kg
- Recommended raw (HTTPS): https://ip6ns.pgwiz.us.kg

Contents
- Quick Start (click-to-copy commands)
- Manual Install (git clone)
- Safety & Verification
- Usage, Troubleshooting & Uninstall
- Contributing & License

---

## Quick Start — Automatic (one‑liner)

Recommended — use HTTPS and prefer download+inspect flow. The one‑liner below executes the installer script directly. This is convenient but risky (it runs remote code).

Click-to-copy (single-line; GitHub shows a "Copy" button on the right of the code block):

```bash
bash <(curl -fsSL https://ip6ns.pgwiz.us.kg)
```

Alternative (pipe to bash):

```bash
curl -fsSL https://ip6ns.pgwiz.us.kg | bash
```

If you need sudo:

```bash
sudo bash <(curl -fsSL https://ip6ns.pgwiz.us.kg)
```

Safer workflow (download, inspect, then run):

```bash
curl -fsSL https://ip6ns.pgwiz.us.kg -o /tmp/ip6ns-installer.sh
less /tmp/ip6ns-installer.sh      # inspect the script
sha256sum /tmp/ip6ns-installer.sh
sudo bash /tmp/ip6ns-installer.sh
```

Open the raw script in your browser (clickable link):
https://ip6ns.pgwiz.us.kg

---

## Manual Install (git clone)

If you prefer to keep a copy under version control and inspect locally:

```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo>
less install.sh           # inspect before running
chmod +x install.sh
sudo ./install.sh
```

Notes:
- Replace https://github.com/<owner>/<repo>.git with the actual repo URL if this project is in a git repo.
- If the installer has a different filename, substitute it.

---

## Make commands easily pastable in README (how this file helps)

- Fenced code blocks are single-line for the one‑liner installers. On GitHub and many markdown renderers, these blocks include a "Copy" button to copy the command to clipboard immediately.
- Each command is presented as a single line (no line breaks) to ensure pasting into a terminal works without editing.
- The raw script link is provided so users can open the script directly in a browser and copy or download it.

---

## Security & Verification

Running remote scripts directly is risky. Recommended steps:

1. Download and inspect before running:
   - curl -fsSL https://ip6ns.pgwiz.us.kg -o /tmp/ip6ns-installer.sh
   - less /tmp/ip6ns-installer.sh

2. Verify checksum (if provided by the maintainer):
   - curl -fsSL https://ip6ns.pgwiz.us.kg/ip6ns-installer.sha256 -o /tmp/ip6ns-installer.sha256
   - sha256sum -c /tmp/ip6ns-installer.sha256
   - If no checksum is available, ask the maintainer to publish one and sign it.

3. Run in a safe environment first (VM, container) to validate behavior.

Security checklist for maintainers (add to repo as needed):
- Publish a signed checksum file (e.g., SHA256 + GPG signature).
- Publish release artifacts on GitHub releases.
- Provide an installation verification command (e.g., --version, --status).

---

## Usage & Verification

Replace the examples below with real commands your script installs or configures.

Examples you can copy:

```bash
# Check installer version (example)
ip6ns --version

# Check service status (if installed as a systemd service)
systemctl status ip6ns.service

# Show installed config (example)
cat /etc/ip6ns/config.conf
```

Troubleshooting:
- Review installer logs (if the installer writes any):
  - /var/log/ip6ns-install.log
- Re-run installer with verbose/debug option (if supported):
  - sudo ./install.sh --debug

---

## Uninstall

If the installer supports uninstall:

```bash
sudo ./install.sh --uninstall
```

If not, document the files the script creates (in the repo) and provide manual removal steps:
- Remove binary: sudo rm /usr/local/bin/ip6ns
- Remove config: sudo rm -rf /etc/ip6ns
- Remove systemd unit: sudo systemctl stop ip6ns.service && sudo systemctl disable ip6ns.service && sudo rm /etc/systemd/system/ip6ns.service

(Replace with the actual files/paths your installer uses.)

---

## Graphics & Visuals

This README includes:
- Shields.io badges at the top for visual cues
- ASCII logo for a quick terminal-friendly visual
- Clickable raw script link for quick browser inspection

If you'd like a screenshot or SVG showing installer output, add an image file to the repo (e.g., docs/screenshot.png) and embed like:

```markdown
![Installer Output](docs/screenshot.png)
```

---

## Contributing

- Fork the repo
- Create a branch: git checkout -b feature/your-change
- Commit, push, and open a PR with a clear description

Include tests and update the README if you change install behavior.

---

## License

Choose a license (e.g., MIT). Add a LICENSE file to the repo.

---

If you want, I can:
- Generate a ready-to-commit README.md with your repo URL and the exact script filename.
- Add a screenshot placeholder image and an example checksum file.
- Create a small assets folder with an SVG badge you prefer.

Tell me which of the above you'd like me to produce and provide the repo URL (if you want a commit-ready file).