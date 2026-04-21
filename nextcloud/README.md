# Nextcloud — Self-Hosted Cloud Storage

## Stack

- Nextcloud 33
- Apache2 (port 80 / 443)
- MariaDB
- PHP 8.x

## Access

| Method | URL |
|--------|-----|
| LAN | http://192.168.2.15 |
| Tailscale | http://100.85.43.39 |

## Quick Setup

```bash
sudo apt install -y apache2 mariadb-server php php-mysql \
  libapache2-mod-php php-xml php-curl php-gd php-zip php-mbstring

wget https://download.nextcloud.com/server/releases/latest.zip
sudo unzip latest.zip -d /var/www/html/
sudo chown -R www-data:www-data /var/www/html/nextcloud
sudo systemctl enable --now apache2
```

Complete the web installer at `http://<server-ip>/nextcloud`.
