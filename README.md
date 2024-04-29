# AngieFastStart

Compile Angie with custom modules on latest Debian and Ubuntu  

## Compatibility

* x86, x64, arm*
* Debian 10 and later
* Ubuntu 18.04 and later

## Features

* Latest mainline or stable version, from source
* Optional modules (see below)
* Removed useless modules
* [Custom angie.conf](https://github.com/FuriousWarrior/AngieFastStart/blob/main/conf/angie.conf) (default does not work)
* [Init script for systemd](https://github.com/FuriousWarrior/AngieFastStart/blob/main/conf/angie.service) (not provided by default)
* [Logrotate conf](https://github.com/FuriousWarrior/AngieFastStart/blob/main/conf/angie-logrotate) (not provided by default)
* Block Angie installation from APT using pinning, to prevent conflicts

### Optional modules/features

* [LibreSSL from source](http://www.libressl.org/) (CHACHA20, ALPN for HTTP/2, X25519, P-521)
* [OpenSSL from source](https://www.openssl.org/) (TLS 1.3, CHACHA20, ALPN for HTTP/2, X25519, P-521)
* [ngx_pagespeed](https://github.com/pagespeed/ngx_pagespeed) (Google performance module)
* [ngx_brotli](https://github.com/eustas/ngx_brotli) (Brotli compression algorithm)
* [ngx_headers_more](https://github.com/openresty/headers-more-nginx-module) (Custom HTTP headers)
* [ngx_http_geoip2_module](https://github.com/leev/ngx_http_geoip2_module) with [libmaxminddb](https://github.com/maxmind/libmaxminddb) and [GeoLite2 databases](https://dev.maxmind.com/geoip/geoip2/geolite2/)
* [ngx_cache_purge](https://github.com/FRiCKLE/ngx_cache_purge) (Purge content from FastCGI, proxy, SCGI and uWSGI caches)
* [ngx-fancyindex](https://github.com/aperezdc/ngx-fancyindex) (Fancy indexes module)
* [nginx-dav-ext-module](https://github.com/arut/nginx-dav-ext-module) (nginx WebDAV PROPFIND,OPTIONS,LOCK,UNLOCK support)
* [nginx-module-vts](https://github.com/vozlt/nginx-module-vts) (Nginx virtual host traffic status module)
  * See install instructions: [nginx-module-vts#installation](https://github.com/vozlt/nginx-module-vts#installation)
* [ModSecurity from source](https://github.com/SpiderLabs/ModSecurity) (ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx)
  * [ModSecurity-nginx](https://github.com/SpiderLabs/ModSecurity-nginx) (ModSecurity v3 Nginx Connector)

## Install Angie

Just download and execute the script :

```sh
wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/angie-autoinstall.sh
chmod +x angie-autoinstall.sh
./angie-autoinstall.sh
```

You can check [configuration examples](https://github.com/FuriousWarrior/AngieFastStart/tree/main/conf) for the custom modules.

## Uninstall Angie

Just select the option when running the script :

You have the choice to delete the logs and the conf.

## Update Angie

To update Angie, run the script and install Angie again. It will overwrite current Angie files and/or modules.

## Update the script

The update feature downloads the script from this repository, and overwrites the current `angie-autoinstall.sh` file in the working directory. This allows you to get the latest features, bugfixes, and module versions automatically.

## Headless use

You can run the script without the prompts with the option `HEADLESS` set to `y`.

```sh
HEADLESS=y ./angie-autoinstall.sh
```

To install Nginx mainline with Brotli:

```sh
HEADLESS=y \
ANGIE_VER=2 \
BROTLI=y \
./angie-autoinstall.sh
```

To uninstall Angie and remove the logs and configuration files:

```sh
HEADLESS=y \
OPTION=2 \
RM_CONF=y \
RM_LOGS=y \
./angie-autoinstall.sh
```

All the default variables are set at the beginning of the script.

## Log file

A log file is created when running the script. It is located at "/tmp/angie-autoinstall.log".

## LICENSE

MIT LICENSE
