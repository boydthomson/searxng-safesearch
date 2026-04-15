# SearXNG Child-Safe Configuration

A hardened SearXNG configuration designed for child-safe browsing. This setup enforces strict safe search with no way for the user to disable it.

## What This Does

- **Strict SafeSearch enforced and locked** -- users cannot change it
- **Curated search engines only** -- Google, Bing, DuckDuckGo, Wikipedia, Stack Overflow, and academic sources (all enforce safe search reliably)
- **Restricted categories** -- only General, Images, Videos, Science, and IT tabs are available (no news, files, social media, torrents, etc.)
- **Preferences locked down** -- safesearch, categories, language, engines, and other settings are all locked from the UI
- **Minimal plugins** -- only Hash and Tracker URL remover (no Self Information plugin that could leak IP details)

## Prerequisites

- A working SearXNG installation ([official docs](https://docs.searxng.org/admin/installation.html))
- Optionally, a reverse proxy (nginx, Caddy, NPM, etc.)
- Family-safe DNS on the client device (e.g., CleanBrowsing, OpenDNS FamilyShield) for defense in depth

## Setup

### 1. Generate a secret key

```bash
openssl rand -hex 32
```

### 2. Install the settings file

Copy `settings-safe.yml` to your SearXNG config directory:

```bash
sudo cp settings-safe.yml /etc/searxng/settings-safe.yml
sudo chown searxng:searxng /etc/searxng/settings-safe.yml
sudo chmod 640 /etc/searxng/settings-safe.yml
```

Edit the file and replace `CHANGE_ME_generate_with_openssl_rand_hex_32` with the key you generated above. Also update `base_url` to match your domain.

### 3. Run as a second instance (alongside an unrestricted one)

Create a systemd service that points to the safe config. For example, create `/etc/systemd/system/searxng-safe.service`:

```ini
[Unit]
Description=SearXNG search engine (Safe Search)
After=network.target

[Service]
Type=simple
User=searxng
Group=searxng
Environment=SEARXNG_SETTINGS_PATH=/etc/searxng/settings-safe.yml
ExecStart=/usr/local/searxng/searx-pyenv/bin/python -m searx.webapp
WorkingDirectory=/usr/local/searxng/searxng-src
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable searxng-safe
sudo systemctl start searxng-safe
```

By default this listens on port **8889**. The unrestricted instance stays on 8888.

### 4. Reverse proxy (optional)

Point a subdomain (e.g., `safesearch.example.com`) at the safe instance. Example nginx location block:

```nginx
location / {
    proxy_pass http://127.0.0.1:8889;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Or in Nginx Proxy Manager, create a Proxy Host pointing to the server IP on port 8889.

### 5. Force the child's device to use it

Combine with:

- **Family-safe DNS** (CleanBrowsing, OpenDNS FamilyShield) to enforce safe search even on Google/Bing directly
- **Browser homepage** set to your safe search domain
- **OS-level parental controls** (Windows Family Safety, macOS Screen Time) to block other search engines
- **Hosts file or browser extension** to redirect google.com/bing.com searches to your safe instance

## Customization

### Adding/removing engines

Edit the `keep_only` list under `use_default_settings.engines`. See the [SearXNG engine list](https://docs.searxng.org/user/configured_engines.html) for available options.

### Adding/removing category tabs

Edit the `categories_as_tabs` section. Available categories: `general`, `images`, `videos`, `news`, `map`, `music`, `it`, `science`, `files`, `social media`.

### Unlocking a preference

Remove it from the `preferences.lock` list.

## License

MIT
