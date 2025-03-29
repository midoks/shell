#!/bin/bash

echo "uninstall mtsf start"

if [ -f /usr/bin/mtsf ];then
	mtsf cron_del
	rm -rf /usr/bin/mtsf
fi

echo "uninstall mtsf end"
