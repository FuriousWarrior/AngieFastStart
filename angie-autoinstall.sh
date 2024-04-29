#!/bin/bash
# shellcheck disable=SC1090,SC2086,SC2034,SC1091,SC2027,SC2206,SC2002

if [[ $EUID -ne 0 ]]; then
	echo -e "Sorry, you need to run this as root"
	exit 1
fi

# Define versions
ANGIE_STABLE_VER=1.5.0
ANGIE_OLD_VER=1.4.1
LIBRESSL_VER=3.9.1
OPENSSL_VER=3.3.0
HEADERMOD_VER=0.37
LIBMAXMINDDB_VER=1.9.1
GEOIP2_VER=3.4

# Define installation paramaters for headless install (fallback if unspecifed)
if [[ $HEADLESS == "y" ]]; then
	OPTION=${OPTION:-1}
	ANGIE_VER=${ANGIE_VER:-1}
	BROTLI=${BROTLI:-n}
	HEADERMOD=${HEADERMOD:-n}
	GEOIP=${GEOIP:-n}
	FANCYINDEX=${FANCYINDEX:-n}
	CACHEPURGE=${CACHEPURGE:-n}
	WEBDAV=${WEBDAV:-n}
	VTS=${VTS:-n}
	zstd=${zstd:-n}
	MODSEC=${MODSEC:-n}
	SSL=${SSL:-1}
	RM_CONF=${RM_CONF:-y}
	RM_LOGS=${RM_LOGS:-y}
fi

# Clean screen before launching menu
if [[ $HEADLESS == "n" ]]; then
	clear
fi

if [[ $HEADLESS != "y" ]]; then
	echo ""
	echo "######################################################" 
	echo "#       Welcome to the angie-autoinstall script.     #"
	echo "#       For Debian 10+ and Ubuntu 16+                #"
	echo "######################################################"
	echo "What do you want to do?"
	echo "   1) Install or update Angie"
	echo "   2) Uninstall Angie"
	echo "   3) Update the script"
	echo "   4) Exit"
	echo ""
	while [[ $OPTION != "1" && $OPTION != "2" && $OPTION != "3" && $OPTION != "4" ]]; do
		read -rp "Select an option [1-4]: " OPTION
	done
fi

case $OPTION in
1)
	if [[ $HEADLESS != "y" ]]; then
		echo ""
		echo "This script will install Angie with some optional modules."
		echo ""
		echo "Do you want to install Angie stable or old stable?"
		echo "   1) Stable $ANGIE_STABLE_VER"
		echo "   2) Mainline $ANGIE_OLD_VER"
		echo ""
		while [[ $ANGIE_VER != "1" && $ANGIE_VER != "2" ]]; do
			read -rp "Select an option [1-2]: " ANGIE_VER
		done
	fi
	case $ANGIE_VER in
	1)
		ANGIE_VER=$ANGIE_STABLE_VER
		;;
	2)
		NANGIE_VER=$ANGIE_OLD_VER
		;;
	*)
		echo "ANGIE_VER unspecified, fallback to stable $ANGIE_STABLE_VER"
		ANGIE_VER=$ANGIE_STABLE_VER
		;;
	esac
	if [[ $HEADLESS != "y" ]]; then
		echo ""
		echo "Please tell me which modules you want to install."
		echo "If you select none, ANGIE will be installed with its default modules."
		echo ""
		echo "Modules to install :"
		while [[ $BROTLI != "y" && $BROTLI != "n" ]]; do
			read -rp "       Brotli [y/n]: " -e BROTLI
		done
		while [[ $HEADERMOD != "y" && $HEADERMOD != "n" ]]; do
			read -rp "       Headers More $HEADERMOD_VER [y/n]: " -e HEADERMOD
		done
		while [[ $GEOIP != "y" && $GEOIP != "n" ]]; do
			read -rp "       GeoIP [y/n]: " -e GEOIP
		done
		while [[ $FANCYINDEX != "y" && $FANCYINDEX != "n" ]]; do
			read -rp "       Fancy index [y/n]: " -e FANCYINDEX
		done
		while [[ $CACHEPURGE != "y" && $CACHEPURGE != "n" ]]; do
			read -rp "       ngx_cache_purge [y/n]: " -e CACHEPURGE
		done
		while [[ $WEBDAV != "y" && $WEBDAV != "n" ]]; do
			read -rp "       nginx WebDAV [y/n]: " -e WEBDAV
		done
		while [[ $VTS != "y" && $VTS != "n" ]]; do
			read -rp "       nginx VTS [y/n]: " -e VTS
		done
		while [[ $zstd != "y" && $zstd != "n" ]]; do
			read -rp "       zstd-ANGIE module for the Zstandard compression.[y/n]: " -e zstd
		done
		while [[ $MODSEC != "y" && $MODSEC != "n" ]]; do
			read -rp "       ANGIE ModSecurity [y/n]: " -e MODSEC
		done
		if [[ $MODSEC == 'y' ]]; then
			read -rp "       Enable ANGIE ModSecurity? [y/n]: " -e MODSEC_ENABLE
		fi

		if [[ $SSLVER != 'y' ]]; then
			echo ""
			echo "Choose your OpenSSL implementation:"
			echo "LibreSSL library is recommended for correct http//3"
			echo "   1) System's OpenSSL ($(openssl version | cut -c9-14))"
			echo "   2) OpenSSL $OPENSSL_VER from source"
			echo "   3) LibreSSL $LIBRESSL_VER from source "
			echo ""
			while [[ $SSL != "1" && $SSL != "2" && $SSL != "3" ]]; do
				read -rp "Select an option [1-3]: " -e -i 3 SSL
			done
		fi
	fi
	if [[ $SSLVER != 'y' ]]; then
		case $SSL in
		1) ;;

		2)
			OPENSSL=y
			;;
		3)
			LIBRESSL=y
			;;
		*)
			echo "SSL unspecified, fallback to system's OpenSSL ($(openssl version | cut -c9-14))"
			;;
		esac
	fi
	if [[ $HEADLESS != "y" ]]; then
		echo ""
		read -n1 -r -p "Angie is ready to be installed, press any key to continue..."
		echo ""
	fi

	# Cleanup
	# The directory should be deleted at the end of the script, but in case it fails
	rm -r /usr/local/src/angie/ >>/dev/null 2>&1
	mkdir -p /usr/local/src/angie/modules

	# Dependencies
	apt-get update
	apt-get install -y build-essential p7zip-full ca-certificates libsodium-dev wget curl libpcre3 libbrotli-dev libpcre3-dev autoconf unzip automake libtool tar git libssl-dev zlib1g-dev uuid-dev lsb-release libxml2-dev libxslt1-dev uthash-dev cmake flex bison gcc-multilib libzstd-dev
	

	if [[ $MODSEC == 'y' ]]; then
		apt-get install -y apt-utils libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre2-dev libyajl-dev pkgconf
	fi

	#Brotli
	if [[ $BROTLI == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli
		cd ngx_brotli/deps/brotli || exit 1
		mkdir out && cd out  || exit 1
		cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_CXX_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_INSTALL_PREFIX=./installed ..
		cmake --build . --config Release --target brotlienc

	fi

	# More Headers
	if [[ $HEADERMOD == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		wget https://github.com/openresty/headers-more-nginx-module/archive/v${HEADERMOD_VER}.tar.gz
		tar xaf v${HEADERMOD_VER}.tar.gz
	fi

	# GeoIP
	if [[ $GEOIP == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		# install libmaxminddb
		wget https://github.com/maxmind/libmaxminddb/releases/download/${LIBMAXMINDDB_VER}/libmaxminddb-${LIBMAXMINDDB_VER}.tar.gz
		tar xaf libmaxminddb-${LIBMAXMINDDB_VER}.tar.gz
		cd libmaxminddb-${LIBMAXMINDDB_VER}/ || exit 1
		./configure
		make
		make install
		ldconfig

		cd ../ || exit 1
		wget https://github.com/leev/ngx_http_geoip2_module/archive/${GEOIP2_VER}.tar.gz
		tar xaf ${GEOIP2_VER}.tar.gz

		mkdir geoip-db
		cd geoip-db || exit 1
		vremya=$(date +"%Y-%m")
		wget https://download.db-ip.com/free/dbip-country-lite-$vremya.mmdb.gz
		wget https://download.db-ip.com/free/dbip-city-lite-$vremya.mmdb.gz
		7z x dbip-country-lite-$vremya.mmdb.gz
		7z x dbip-city-lite-$vremya.mmdb.gz
		mkdir /opt/geoip
		mv dbip-country-lite-$vremya.mmdb /opt/geoip/
		mv dbip-city-lite-$vremya.mmdb /opt/geoip/
		rm dbip-country-lite-$vremya.mmdb.gz
		rm dbip-city-lite-$vremya.mmdb.gz
	fi

	# Cache Purge
	if [[ $CACHEPURGE == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		git clone https://github.com/FRiCKLE/ngx_cache_purge
	fi

	# LibreSSL
	if [[ $LIBRESSL == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		mkdir libressl-${LIBRESSL_VER}
		cd libressl-${LIBRESSL_VER} || exit 1
		wget -qO- http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER}.tar.gz | tar xz --strip 1

		./configure \
			LDFLAGS=-lrt \
			CFLAGS=-fstack-protector-strong \
			--prefix=/usr/local/src/nginx/modules/libressl-${LIBRESSL_VER}/.openssl/ \
			--enable-shared=no

		make install-strip -j "$(nproc)"
	fi

	# OpenSSL
	if [[ $OPENSSL == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		wget https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz
		tar xaf openssl-${OPENSSL_VER}.tar.gz
		cd openssl-${OPENSSL_VER} || exit 1
		./config
	fi

	# zstd-nginx-module https://github.com/facebook/zstd https://github.com/tokers/zstd-nginx-module
	if [[ $zstd == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		git clone https://github.com/tokers/zstd-nginx-module.git
		cd /usr/local/src || exit 1
		git clone https://github.com/facebook/zstd.git
		cd /usr/local/src/zstd || exit 1
		make
		make install
	fi
	# ModSecurity
	if [[ $MODSEC == 'y' ]]; then
		cd /usr/local/src/angie/modules || exit 1
		git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
		cd ModSecurity || exit 1
		git submodule init
		git submodule update
		./build.sh
		./configure --with-maxmind=no
		make
		make install
		mkdir -p /etc/angie/modsec/
		wget -P /etc/angie/modsec/ https://raw.githubusercontent.com/FuriousWarrior/NginxFastStart/main/conf/main.conf
		wget -P /etc/angie/modsec/ https://raw.githubusercontent.com/FuriousWarrior/NginxFastStart/main/conf/modsecurity.conf

		# Enable ModSecurity in Nginx
		if [[ $MODSEC_ENABLE == 'y' ]]; then
			sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
		fi
		# OWASP Rules
		wget -P /etc/angie/modsec/ https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.1.0.tar.gz
		cd /etc/angie/modsec/ || exit 1
		tar -xf v4.1.0.tar.gz
		cd coreruleset-4.1.0 || exit 1
		cp crs-setup.conf.example crs-setup.conf
	fi

	# Download and extract of Angie source code  1.5.0.tar.gz
	cd /usr/local/src/angie/ || exit 1
	wget -qO- https://download.angie.software/files/angie-${ANGIE_VER}.tar.gz | tar zxf -
	cd angie-${ANGIE_VER} || exit 1

	# As the default angie.conf does not work, we download a clean and working conf from my GitHub.
	# We do it only if it does not already exist, so that it is not overriten if Nginx is being updated
	if [[ ! -e /etc/nginx/nginx.conf ]]; then
		mkdir -p /etc/nginx
		cd /etc/nginx || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/conf/angie.conf
	fi
	cd /usr/local/src/angie/angie-${ANGIE_VER} || exit 1

	ANGIE_OPTIONS="
		--prefix=/etc/angie \
		--sbin-path=/usr/sbin/angie \
		--conf-path=/etc/angie/angie.conf \
		--error-log-path=/var/log/angie/error.log \
		--http-log-path=/var/log/angie/access.log \
		--pid-path=/var/run/angie.pid \
		--lock-path=/var/run/angie.lock \
		--http-client-body-temp-path=/var/cache/angie/client_temp \
		--http-proxy-temp-path=/var/cache/angie/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/angie/fastcgi_temp \
		--user=angie \
		--group=angie \
		--with-cc-opt=-fstack-protector \
		--with-cc-opt=-fstack-protector-strong \
		--with-cc-opt=--param=ssp-buffer-size=4 \
		--with-cc-opt=-Wformat \
		--with-cc-opt=-Werror=format-security \
		--with-cc-opt=-Werror=implicit-function-declaration \
		--with-cc-opt=-fPIC \
		--with-cc-opt=-Werror=deprecated-declarations \
		--with-cc-opt=-Wno-error=name_of_warning \
		--with-cc-opt=-Wno-ignored-qualifiers"
	ANGIE_MODULES="--with-threads \
		--with-compat \
		--with-file-aio \
		--with-http_ssl_module \
		--with-http_v2_module \
		--with-http_v3_module \
		--with-http_mp4_module \
		--with-http_auth_request_module \
		--with-http_slice_module \
		--with-http_stub_status_module \
		--with-http_realip_module \
		--with-http_sub_module \
		--with-http_gunzip_module \
		--with-stream \
		--with-stream_ssl_module \
		--with-stream_realip_module\
        --with-stream_ssl_preread_module"

	# Optional modules
	if [[ $LIBRESSL == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo --with-openssl=/usr/local/src/angie/modules/libressl-${LIBRESSL_VER}
		)
	fi

	if [[ $BROTLI == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo "--add-module=/usr/local/src/angie/modules/ngx_brotli"
		)
	fi

	if [[ $HEADERMOD == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo "--add-module=/usr/local/src/angie/modules/headers-more-nginx-module-${HEADERMOD_VER}"
		)
	fi

	if [[ $GEOIP == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo "--add-module=/usr/local/src/angie/modules/ngx_http_geoip2_module-${GEOIP2_VER}"
		)
	fi

	if [[ $OPENSSL == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo "--with-openssl=/usr/local/src/angie/modules/openssl-${OPENSSL_VER}"
		)
	fi

	if [[ $CACHEPURGE == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo "--add-module=/usr/local/src/angie/modules/ngx_cache_purge"
		)
	fi

	if [[ $FANCYINDEX == 'y' ]]; then
		git clone --depth 1 --quiet https://github.com/aperezdc/ngx-fancyindex.git /usr/local/src/angie/modules/fancyindex
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo --add-module=/usr/local/src/angie/modules/fancyindex
		)
	fi

	if [[ $WEBDAV == 'y' ]]; then
		git clone --depth 1 --quiet https://github.com/arut/nginx-dav-ext-module.git /usr/local/src/angie/modules/nginx-dav-ext-module
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo --with-http_dav_module --add-module=/usr/local/src/angie/modules/nginx-dav-ext-module
		)
	fi

	if [[ $VTS == 'y' ]]; then
		git clone --depth 1 --quiet https://github.com/vozlt/nginx-module-vts.git /usr/local/src/angie/modules/nginx-module-vts
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo --add-module=/usr/local/src/angie/modules/nginx-module-vts
		)
	fi

	if [[ $zstd == 'y' ]]; then
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo "--add-module=/usr/local/src/angie/modules/zstd-nginx-module"
		)
	fi

	if [[ $MODSEC == 'y' ]]; then
		git clone --depth 1 --quiet https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/angie/modules/ModSecurity-nginx
		ANGIE_MODULES=$(
			echo "$ANGIE_MODULES"
			echo --add-module=/usr/local/src/angie/modules/ModSecurity-nginx
		)
	fi

	./configure $ANGIE_OPTIONS $ANGIE_MODULES
	make -j "$(nproc)"
	make install

	# remove debugging symbols
	strip -s /usr/sbin/angie

	# angie installation from source does not add an init script for systemd and logrotate
	if [[ ! -e /lib/systemd/system/angie.service ]]; then
		cd /lib/systemd/system/ || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/conf/nginx.service
		# Enable angie start at boot
		systemctl enable angie
	fi

	if [[ ! -e /etc/logrotate.d/angie ]]; then
		cd /etc/logrotate.d/ || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/conf/nginx-logrotate -O angie
	fi

	# angie's cache directory is not created by default
	if [[ ! -d /var/cache/angie ]]; then
		mkdir -p /var/cache/angie
	fi

	# We add the sites-* folders as some use them.
	if [[ ! -d /etc/angie/sites-available ]]; then
		mkdir -p /etc/angie/sites-available
	fi
	if [[ ! -d /etc/angie/sites-enabled ]]; then
		mkdir -p /etc/angie/sites-enabled
	fi
	if [[ ! -d /etc/angie/ssl ]]; then
		mkdir -p /etc/angie/ssl
	fi
	if [[ ! -d /etc/angie/global ]]; then
		mkdir -p /etc/angie/global
	fi
	if [[ ! -d /etc/angie/conf.d ]]; then
		mkdir -p /etc/angie/conf.d
	fi

	if [[ ! -e /etc/angie/ssl/ssl.conf ]]; then
		cd /etc/angie/ssl || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/conf/ssl.conf
	fi

	if [[ ! -e /etc/angie/global/security.conf ]]; then
		cd /etc/angie/global || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/conf/security.conf
	fi

	if [[ ! -e /etc/angie/global/global.conf ]]; then
		cd /etc/angie/global || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/global/global.conf
	fi

	if [[ ! -e /etc/angie/global/proxy.conf ]]; then
		cd /etc/angie/global || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/global/proxy.conf
	fi

	if [[ ! -e /etc/angie/global/php_fastcgi.conf ]]; then
		cd /etc/angie/global || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/global/php_fastcgi.conf
	fi

	if [[ ! -e /etc/angie/global/python_uwsgi.conf ]]; then
		cd /etc/angie/global || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/global/python_uwsgi.conf
	fi

	# Example Configs
	if [[ ! -e /etc/angie/sites-available/example.com.conf ]]; then
		cd /etc/angie/sites-available || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/sites-available/example.com.conf
	fi

	if [[ ! -e /etc/angie/sites-available/example.django.com.conf ]]; then
		cd /etc/angie/sites-available || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/sites-available/example.django.com.conf 
	fi

	if [[ ! -e /etc/angie/sites-available/example.php.com.conf ]]; then
		cd /etc/angie/sites-available || exit 1
		wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/sites-available/example.php.com.conf
	fi

	# Restart Nginx
	systemctl restart angie

	# Block angie from being installed via APT
	if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]; then
		cd /etc/apt/preferences.d/ || exit 1
		echo -e 'Package: angie*\nPin: release *\nPin-Priority: -1' >angie-block
	fi

	# Remove conf files
	if [[ $RM_CONF == 'y' ]]; then
		rm -r /etc/angie/
	fi

	# Remove logs
	if [[ $RM_LOGS == 'y' ]]; then
		rm -r /var/log/angie
	fi

	# Remove angie APT block
	if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]; then
		rm /etc/apt/preferences.d/angie-block
	fi

	# We're done !
	echo "Uninstallation done."

	exit
	;;
3) # Update the script
	wget https://raw.githubusercontent.com/FuriousWarrior/AngieFastStart/main/angie-autoinstall.sh -O angie-autoinstall.sh
	chmod +x angie-autoinstall.sh
	echo ""
	echo "Update done."
	sleep 2
	./angie-autoinstall.sh
	exit
	;;
*) # Exit
	exit
	;;

esac

