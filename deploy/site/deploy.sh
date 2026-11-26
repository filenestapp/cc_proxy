#!/usr/bin/env bash
# Upload site/ to the aifree.sg web root and reload nginx.
# Usage: deploy/site/deploy.sh [ssh-target]   (default ubuntu@43.156.58.218)
set -euo pipefail
target=${1:-ubuntu@43.156.58.218}
root=$(cd "$(dirname "$0")/../.." && pwd)
stage=/tmp/aifree-site.$$

# Dereference the desktop chooser shared with the control plane when staging the static site.
rsync -aL --delete --exclude README.md --exclude _headers "$root/site/" "$target:$stage/"
scp -q "$root/deploy/site/aifree.sg.conf" "$target:$stage.conf"
ssh "$target" "set -e
  sudo mkdir -p /www/wwwroot/aifree.sg /var/lib/aifree-site/acme
  sudo rsync -a --delete $stage/ /www/wwwroot/aifree.sg/
  sudo chown -R www:www /www/wwwroot/aifree.sg
  sudo install -m 644 $stage.conf /www/server/panel/vhost/nginx/aifree.sg.conf
  rm -rf $stage $stage.conf
  sudo /www/server/nginx/sbin/nginx -t -c /www/server/nginx/conf/nginx.conf
  sudo /www/server/nginx/sbin/nginx -s reload -c /www/server/nginx/conf/nginx.conf"
echo "deployed to https://aifree.sg"
