#!/bin/bash

echo "install mtsf start"

which 

if [ ! -f /usr/bin/mtsf ];then
	wget -O /usr/bin/mtsf https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/mtsf.sh
	chmod +x /usr/bin/mtsf
fi

echo "install mtsf end"
