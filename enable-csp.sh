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
Header add Content-Security-Policy "base-uri 'none'; default-src 'self'; img-src 'self' data: https:; object-src 'none'; script-src 'strict-dynamic' 'nonce-rAnd0m123' 'unsafe-inline' http: https:; require-trusted-types-for 'script'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';"
# Anti-clickjacking Header
Header always set X-Frame-Options "SAMEORIGIN"
# X-Content-Type-Options Header
Header always set X-Content-Type-Options "nosniff"

# SSL Config
SSLEngine on
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5
SSLHonorCipherOrder on
SSLCompression off

# HTTP debugging methods configuration
TraceEnable off

# SCM deny config
RedirectMatch 404 /\.(svn|git|hg|bzr|CSV)(/|$)

<Location /robots.txt>
RewriteEngine On
RewriteCond %{REQUEST_URI} "^/robots.txt" [NC]
RewriteRule "^.*$" - [F,L]
</Location>
EOL

cat << 'EOL' > "$temp_content_file_http"
# Content Security Policy Header
Header add Content-Security-Policy "base-uri 'none'; default-src 'self'; img-src 'self' data: https:; object-src 'none'; script-src 'strict-dynamic' 'nonce-rAnd0m123' 'unsafe-inline' http: https:; require-trusted-types-for 'script'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';"
# Anti-clickjacking Header
Header always set X-Frame-Options "SAMEORIGIN"
# X-Content-Type-Options Header
Header always set X-Content-Type-Options "nosniff"

# HTTP debugging methods configuration
TraceEnable off

# SCM deny config
RedirectMatch 404 /\.(svn|git|hg|bzr|CSV)(/|$)

<Location /robots.txt>
RewriteEngine On
RewriteCond %{REQUEST_URI} "^/robots.txt" [NC]
RewriteRule "^.*$" - [F,L]
</Location>
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
