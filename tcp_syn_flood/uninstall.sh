#!/bin/bash

echo "uninstall mtsf start"

mtsf cron_del
if [ -f /usr/bin/mtsf ];then
	rm -rf /usr/bin/mtsf
fi

echo "uninstall mtsf end"
