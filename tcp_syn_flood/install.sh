#!/bin/bash


echo "install mtsf start"
if [ ! -f /usr/bin/mtsf ];then
	wget -0 /usr/bin/mtsf https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/mtsf.sh
fi

echo "install mtsf end"
