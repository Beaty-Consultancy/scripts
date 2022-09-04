#!/bin/bash

# File Name:    headscale.sh
# Description:  Install and configure HeadScale as a lighthouse server
# Version:      1
# Author:       Ricky Beaty
# Date:         25/08/2022

#######################################

# Check if a swap file is present
if free | awk '/^Swap:/ {exit !$2}'; then
    echo "Have swap, skipping"
else
    # Add 2GB swapfile to root volume - ClamScan can be memory hungry
    /bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=2048
    chmod 600 /var/swap.1
    /sbin/mkswap /var/swap.1
    /sbin/swapon /var/swap.1
    # Write out to fstab to retain the swapfile config on reboot
    echo "/var/swap.1   swap    swap    sw  0   0" >> /etc/fstab
fi

# Add ricky's public key
adduser ricky --gecos "Ricky Beaty,NA,NA,NA" --disabled-password
su -c 'mkdir /home/ricky/.ssh' ricky 
su -c 'chmod 700 /home/ricky/.ssh' ricky
su -c 'touch /home/ricky/.ssh/authorized_keys' ricky
curl https://bc-public.s3.eu-west-2.amazonaws.com/ricky.pub >> /home/ricky/.ssh/authorized_keys
chmod 600 /home/ricky/.ssh/authorized_keys
echo "ricky ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users

# Install latest version of docker from Docker's own repos
apt update
apt -y upgrade

apt-get remove docker docker-engine docker.io containerd runc
apt-get update
apt-get install \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-compose

# Deploy Headscale
mkdir -p ./headscale/config
mkdir -p ./headscale/data
cd ./headscale
touch ./config/db.sqlite
curl https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml -o ./config/config.yaml
sed -i -e 's|server_url: http://127.0.0.1:8080|server_url: https://headscale.beatyconsultancy.co.uk|g' ./config/config.yaml
sed -i -e 's|metrics_listen_addr: 127.0.0.1:9090|metrics_listen_addr: 0.0.0.0:9090|g' ./config/config.yaml
sed -i -e 's|private_key_path: /var/lib/headscale/private.key|private_key_path: /etc/headscale/private.key|g' ./config/config.yaml
sed -i -e 's|private_key_path: /var/lib/headscale/noise_private.key|private_key_path: /etc/headscale/noise_private.key|g' ./config/config.yaml
sed -i -e 's|db_path: /var/lib/headscale/db.sqlite|db_path: /etc/headscale/db.sqlite|g' ./config/config.yaml

# Set up docker-compose for nginx and certbot in front of Headscale
cat <<EOF > docker-compose.yml
version: '3'
services:
  nginx:
    image: nginx:1.15-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./data/nginx:/etc/nginx/conf.d
      - ./data/certbot/conf:/etc/letsencrypt
      - ./data/certbot/www:/var/www/certbot
    networks:
      main:
        aliases:
          - web
  certbot:
    image: certbot/certbot
    volumes:
      - ./data/certbot/conf:/etc/letsencrypt
      - ./data/certbot/www:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait \$\${!}; done;'"
  headscale:
    image: headscale/headscale:latest
    volumes:
      - ./config:/etc/headscale/
      - ./data/headscale:/var/lib/headscale
    ports:
      - 27896:8080
    networks:
      main:
        aliases:
          - headscale
    command: headscale serve
    restart: unless-stopped

networks:
  main:
EOF

# Create NginX config
mkdir -p data/nginx
cat <<EOF > data/nginx/app.conf
server {
    listen 80;
    server_name headscale.beatyconsultancy.co.uk;
    location / {
        return 301 https://\$host\$request_uri;
    }
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
}

upstream docker-headscale {
    server web:27896;
}

server {
    listen 443 ssl;
    server_name headscale.beatyconsultancy.co.uk;
    
    location / {
        proxy_pass http://docker-headscale;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_redirect default;
    }

    ssl_certificate /etc/letsencrypt/live/headscale.beatyconsultancy.co.uk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/headscale.beatyconsultancy.co.uk/privkey.pem;

    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
EOF

# Set up dummy cert so we can start the stack without first having the pucka cert;
curl -L https://raw.githubusercontent.com/wmnnd/nginx-certbot/master/init-letsencrypt.sh > init-letsencrypt.sh
sed -i -e 's|(example.org www.example.org)|(headscale.beatyconsultancy.co.uk)|g' init-letsencrypt.sh
sed -i -e 's|email=""|email="ricky@beatyconsultancy.co.uk"|g' init-letsencrypt.sh

chmod +x init-letsencrypt.sh
./init-letsencrypt.sh