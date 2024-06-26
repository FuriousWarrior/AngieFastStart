#!/bin/bash

export HEADLESS=y

if [[ $INSTALL_TYPE == "FULL" ]]; then
    export BROTLI=y
    export HEADERMOD=y
    export GEOIP=y
    export FANCYINDEX=y
    export CACHEPURGE=y
    export WEBDAV=y
    export VTS=y
    export zstd=n
    export MODSEC=n
fi

bash -x ../../angie-autoinstall.sh