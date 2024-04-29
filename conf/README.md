# Configurations files

## PageSpeed

Add this in your http block:

```nginx
pagespeed on;
pagespeed StatisticsPath /ngx_pagespeed_statistics;
pagespeed GlobalStatisticsPath /ngx_pagespeed_global_statistics;
pagespeed MessagesPath /ngx_pagespeed_message;
pagespeed ConsolePath /pagespeed_console;
pagespeed AdminPath /pagespeed_admin;
pagespeed GlobalAdminPath /pagespeed_global_admin;
# Needs to exist and be writable by nginx.
# Use tmpfs for best performance.
pagespeed FileCachePath /var/ngx_pagespeed_cache;
```

## Brotli

Add this in your http block :

```nginx
brotli on;
brotli_static on;
brotli_buffers 16 8k;
brotli_comp_level 6;
brotli_types *;
```

## LibreSSL / OpenSSL 1.1+

You can now use ChaCha20 in addition to AES. Add this in your server block:

```nginx
ssl_ciphers EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
```

You can also use more secure curves :

```nginx
ssl_ecdh_curve X25519:P-521:P-384:P-256;
```

## TLS 1.3

TLS 1.3 needs special ciphers.

```nginx
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:TLS-AES-128-GCM-SHA256:EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
```

TLS- can be TLS13-.

## GeoIP 2

See <https://github.com/leev/ngx_http_geoip2_module#example-usage>


## ModSecurity

```nginx
server {
    listen 80;
 modsecurity on;
 modsecurity_rules_file /etc/nginx/modsec/main.conf;

# If you have proxy
    location / {     
     proxy_pass http://192.168.x.x;
    }
}
```

## OWASP rules

/etc/nginx/modsec/main.conf:

```nginx
# OWASP CRS v3 rules
Include /etc/nginx/modsec/coreruleset-3.3.4/crs-setup.conf
Include /etc/nginx/modsec/coreruleset-3.3.4/rules/*.conf
```

## zstd-nginx-module

```zstd
# specify the dictionary
zstd_dict_file /path/to/dict;

server {
    listen 127.0.0.1:8080;
    server_name localhost;

    location / {
        # enable zstd compression
        zstd on;
        zstd_min_length 256; # no less than 256 bytes
        zstd_comp_level 3; # set the level to 3

        proxy_pass http://foo.com;
    }
}

server {
    listen 127.0.0.1:8081;
    server_name localhost;

    location / {
        zstd_static on;
        root html;
    }
}
```