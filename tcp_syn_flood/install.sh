#!/bin/bash

echo "install mtsf start"

TIME=`date +"%Y_%m_%d_%H_%M_%S"`

if [ ! -f /usr/bin/mtsf ];then
	wget -O /usr/bin/mtsf https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/mtsf.sh?t=${TIME}
	chmod +x /usr/bin/mtsf
fi

echo "install mtsf end"
