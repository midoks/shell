#!/bin/bash

echo "install mtsf start"

TIME=`date +"%Y_%m_%d_%H_%M_%S"`

echo "time:$TIME"

which apt && apt install -y net-tools
which apt && apt install -y conntrack
which apt && apt install -y geoip-bin
which apt && apt install -y at
which apt && apt install -y iptables
which apt && apt install -y iftop
which apt && apt install -y bc
which apt && apt install -y ethtool
which apt && apt install -y irqbalance
which apt && apt install -y cron
which apt && apt install -y ntp
# ntpd
# which apt && apt install -y tcpdump

if [ ! -f /usr/bin/mtsf ];then
	wget -O /usr/bin/mtsf https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/mtsf.sh?t=${TIME}
	chmod +x /usr/bin/mtsf
fi

if [ ! -f /var/spool/cron/crontabs/root ];then
	touch /var/spool/cron/crontabs/root
fi


# FIND_MTSF_CRON=`cat /var/spool/cron/crontabs/root | grep "mtsf run"`
# if [ "$FIND_MTSF_CRON" == "" ];then
# 	CHOICE_IS_ADD_CRON=$(echo -e "\n是否加入计划任务执行[Y/N]:")
# 	read -p "${CHOICE_IS_ADD_CRON}" INPUT
# 	# echo "INPUT:$INPUT"
# 	if [ "$INPUT" == "Y" ];then
# 		mtsf cron_add
# 	fi
# fi

mtsf chinese_gc
mtsf o
mtsf
mtsf v

# mtsf to_cubic

