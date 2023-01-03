domain=''

# Install certbot into ubuntu
add-apt-repository -y ppa:certbot/certbot
apt-get update 
apt install -y certbot 

# Issue the cert
certbot certonly --standalone --preferred-challenges http -d $domain

# Add the cert files into OpenVPN config
/usr/local/openvpn_as/scripts/sacli --key "cs.priv_key" --value_file "/etc/letsencrypt/live/$domain/privkey.pem" ConfigPut
/usr/local/openvpn_as/scripts/sacli --key "cs.cert" --value_file "/etc/letsencrypt/live/$domain/fullchain.pem" ConfigPut
/usr/local/openvpn_as/scripts/sacli start


# Renew script isn't needed anymore because certbot sets up a systemd timer instead.  Cool beans!
# # Renew script -> /usr/local/sbin/certrenewal.sh
# cat <<EOT >> /usr/local/sbin/certrenewal.sh
# #!/bin/bash
# certbot renew — standalone
# sleep 1m
# /usr/local/openvpn_as/scripts/sacli --key "cs.priv_key" --value_file "/etc/letsencrypt/live/$domain/privkey.pem" ConfigPut

# /usr/local/openvpn_as/scripts/sacli --key "cs.cert" --value_file "/etc/letsencrypt/live/$domain/fullchain.pem" ConfigPut

# /usr/local/openvpn_as/scripts/sacli start
# EOT

# # Make it executable
# chmod +x /usr/local/sbin/certrenewal.sh

# # Add a cron job which runs every 2.5 months;
# (crontab -l ; echo "0 * 15 */2 * /usr/local/sbin/certrenewal.sh")| crontab -


# # Sauce - https://medium.com/@ncsayeed/guide-openvpn-access-server-lets-encrypt-certbot-d8b65e8fdef
