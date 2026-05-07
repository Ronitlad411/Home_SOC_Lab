# Nextcloud Gallery

> **Self-hosted cloud storage and photo gallery — Nextcloud on Apache2/MariaDB with a custom Flask frontend**

---

Personal photos sitting on someone else's servers stopped feeling acceptable. Nextcloud Gallery is the answer — full-stack cloud storage running on hardware at home, reachable from anywhere over Tailscale, with no third party in the middle. Nextcloud handles the storage layer on Apache2 and MariaDB, and a custom Flask app sits on top to serve the photo gallery experience. Building it end to end meant configuring the web server, the database, the application layer, and the access controls — the same surface area that an enterprise on-prem or hybrid cloud environment exposes.

---

## Features

- Browse and view photos served from Nextcloud over WebDAV
- Subfolder navigation with breadcrumbs
- Photo lightbox and inline video playback
- Local media route for files stored at `/opt/photo-gallery/media/`
- Dual-IP auto-detection (LAN with Tailscale fallback)

---

## Stack

| Component | Tool |
|---|---|
| Cloud platform | Nextcloud 33 |
| Web server | Apache2 |
| Database | MariaDB |
| Runtime | PHP 8.3 |
| Gallery app | Flask (Python 3) |
| Remote access | Tailscale |

---

## Deployment

```bash
# Nextcloud
sudo apt install -y apache2 mariadb-server php php-mysql \
  libapache2-mod-php php-xml php-curl php-gd php-zip php-mbstring
wget https://download.nextcloud.com/server/releases/latest.zip
sudo unzip latest.zip -d /var/www/html/
sudo chown -R www-data:www-data /var/www/html/nextcloud

# Photo Gallery
sudo pip3 install flask --break-system-packages
sudo cp -r . /opt/photo-gallery/
sudo systemctl enable --now photo-gallery
```

---

## Ports

| Port | Service |
|---|---|
| 80 | Nextcloud HTTP (Apache2) |
| 443 | Nextcloud HTTPS |
| 5001 | Photo Gallery Flask app |
