#!/bin/bash

echo "uninstall mtsf start"

if [ -f /usr/bin/mtsf ];then
	rm -rf /usr/bin/mtsf
fi

echo "uninstall mtsf end"
