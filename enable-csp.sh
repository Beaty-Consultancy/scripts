#!/bin/bash

# File Name:    enable-csp.sh
# Description:  Enable CSP Headers on httpd
# Version:      1
# Author:       Ahmed
# Date:         09/10/2023
# Prerequisites Ensure mod_headers and mod_ssl is enabled
#               httpd -t -D DUMP_MODULES | grep header
#               

#######################################

# Define the Apache configuration file
config_file_https="/etc/httpd/conf/httpd-le-ssl.conf"
config_file_http="/etc/httpd/conf/httpd.conf"

# Define a temporary file for the content to be appended
temp_content_file_https="/tmp/content_to_append_https.conf"
touch "$temp_content_file_https"

temp_content_file_http="/tmp/content_to_append_http.conf"
touch "$temp_content_file_http"

# Define the content to be appended
cat << 'EOL' > "$temp_content_file_https"

# Strict-Transport-Security Header
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Content Security Policy Header
Header add Content-Security-Policy "base-uri 'none'; default-src 'self'; img-src 'self'; object-src 'none'; script-src 'self' https://dev.changemyface.com; require-trusted-types-for 'script'; connect-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self'; worker-src 'none';"

# Anti-clickjacking Header
Header always set X-Frame-Options "SAMEORIGIN"

# X-Content-Type-Options Header
Header always set X-Content-Type-Options "nosniff"

#Cache control Header
Header set Cache-Control "no-cache, no-store, must-revalidate"


#SSL Config
SSLEngine on
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!3DES
SSLHonorCipherOrder on
SSLCompression off

# HTTP debugging methods configuration
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
RewriteRule .* - [F]

#SCM deny config
RedirectMatch 404 /\.(svn|git|hg|bzr|csv)(/|$)

SSLCertificateFile /etc/letsencrypt/live/dev.changemyface.com/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/dev.changemyface.com/privkey.pem

EOL

cat << 'EOL' > "$temp_content_file_http"

# HTTP debugging methods configuration
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
RewriteRule .* - [F]

EOL

# Use awk to locate <VirtualHost *:443> block and append content
awk -v content_file="$temp_content_file_https" '
    /<VirtualHost \*:443>/ {
        found=1;
        print;  # Print the line
        while (getline) {
            if (/<\/VirtualHost>/) {  # End of the VirtualHost block
                close(content_file);
                system("cat " content_file);  # Append the content
                found=0;
            }
            print;
        }
    }
    !found {
        print;  # Print lines outside of the VirtualHost block
    }
' "$config_file_https" > "$config_file_https.tmp"

# Use awk to locate <VirtualHost *:80> block and append content
awk -v content_file="$temp_content_file_http" '
    /<VirtualHost \*:80>/ {
        found=1;
        print;  # Print the line
        while (getline) {
            if (/<\/VirtualHost>/) {  # End of the VirtualHost block
                close(content_file);
                system("cat " content_file);  # Append the content
                found=0;
            }
            print;
        }
    }
    !found {
        print;  # Print lines outside of the VirtualHost block
    }
' "$config_file_http" > "$config_file_http.tmp"

# Overwrite the original file with the modified content
mv "$config_file_https.tmp" "$config_file_https"
mv "$config_file_http.tmp" "$config_file_http"

# Remove the temporary content file
rm "$temp_content_file_https"
rm "$temp_content_file_http"

# Restart Apache to apply the changes
sudo systemctl restart httpd
