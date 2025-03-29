#!/bin/bash

PATH=/usr/local/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PLAIN="\033[0m"
BOLD="\033[1m"
CEND="\033[0m"
SUCCESS=$GREEN'OK'${CEND}
COMPLETE=$GREEN'DONE'${CEND}
WARN=$YELLOW'WARN'${CEND}
ERROR=$RED'ERROR'${CEND}
WORKING=$BLUE'*'${CEND}

MF_VERSION(){
	echo "mtsf - 0.0.31"
}

MF_GET_SUBNET(){
	# 输入IP地址和掩码
	IP="$1"
	MASK="24" # 可以修改为 16、8 等

	# 根据掩码计算网络部分
	IFS='.' read -r i1 i2 i3 i4 <<< "$IP"

	if [ "$MASK" -eq 24 ]; then
	    NETWORK="$i1.$i2.$i3.0"
	elif [ "$MASK" -eq 16 ]; then
	    NETWORK="$i1.$i2.0.0"
	elif [ "$MASK" -eq 8 ]; then
	    NETWORK="$i1.0.0.0"
	else
	    echo "不支持的掩码: $MASK"
	    exit 1
	fi
	# 添加掩码
	SUBNET="$NETWORK/$MASK"
	echo $SUBNET
}

MF_GET_PRESTR(){
	IP="$1"
	IFS='.' read -r i1 i2 i3 i4 <<< "$IP"
	echo $i1.$i2.$i3
}

MF_BAN_DO(){
	SUBNET_IP="$1"
	FIND_SUBNET_IP=`iptables -L -n | grep $SUBNET_IP`
	if [[ "$FIND_SUBNET_IP" == "" ]];then
		echo "IP $SUBNET_IP 来自 $COUNTRY，将被封禁5分钟。"
	    # 封禁IP地址
	    echo "iptables -A INPUT -s $SUBNET_IP -j DROP"

	    IPTABLES_CMD=$(which iptables)
		if [ -z "$IPTABLES_CMD" ]; then
		    echo "iptables 未安装或未找到，请先安装 iptables。"
		    exit 1
		fi
	    echo "${IPTABLES_CMD} -A INPUT -s $SUBNET_IP -j DROP"
	    ${IPTABLES_CMD} -A INPUT -s $SUBNET_IP -j DROP

	   	# iptables -A INPUT -s 192.3.171.0/24 -j DROP
	   	# iptables -A INPUT -s 192.3.171.0/24 -j DROP

	   	# iptables -D OUTPUT -s 192.3.171.0/24 -j DROP
	   	# iptables -D OUTPUT -s 192.3.171.0/24 -j DROP

	    echo "${IPTABLES_CMD} -A OUTPUT -d $SUBNET_IP -j DROP"
	    ${IPTABLES_CMD} -A OUTPUT -d $SUBNET_IP -j DROP

	    # 5分钟后解封
	    echo "iptables -D INPUT -s $SUBNET_IP -j DROP" | at now + 10 minutes
	    echo "iptables -D OUTPUT -d $SUBNET_IP -j DROP" | at now + 10 minutes

	    echo "${SUBNET_IP} 5分钟后解封"
	else
		echo "IP $SUBNET_IP 来自 $COUNTRY，已经封禁。"
	fi
}

MF_BAN_DO1(){
	SUBNET_IP="$1"
	FIND_SUBNET_IP=`iptables -L -n | grep $SUBNET_IP`
	if [[ "$FIND_SUBNET_IP" == "" ]];then
		echo "IP $SUBNET_IP 来自 $COUNTRY，将被封禁5分钟。"
	    # 封禁IP地址
	    echo "iptables -A INPUT -s $SUBNET_IP -j DROP"

	    IPTABLES_CMD=$(which iptables)
		if [ -z "$IPTABLES_CMD" ]; then
		    echo "iptables 未安装或未找到，请先安装 iptables。"
		    exit 1
		fi
	    echo "${IPTABLES_CMD} -A INPUT -s $SUBNET_IP -j DROP"
	    ${IPTABLES_CMD} -A INPUT -s $SUBNET_IP -j DROP

	    echo "${IPTABLES_CMD} -A OUTPUT -d $SUBNET_IP -j DROP"
	    ${IPTABLES_CMD} -A OUTPUT -d $SUBNET_IP -j DROP
	    # 5分钟后解封
	    echo "iptables -D INPUT -s $SUBNET_IP -j DROP" | at now + 3 minutes
	    echo "iptables -D OUTPUT -d $SUBNET_IP -j DROP" | at now + 3 minutes
	    echo "${SUBNET_IP} 1分钟后解封"
	else
		echo "IP $SUBNET_IP 来自 $COUNTRY，已经封禁。"
	fi
}

RUN_CMD_SYN_RECV(){
		netstat -an | grep SYN_RECV | while read line; do
		# echo $line
		SRC_IP=$(echo "$line" | awk '{print $5}' | cut -d= -f2)
		# echo "SRC_IP:$SRC_IP"

		# 获取IP地址
		IP=$(echo $SRC_IP | cut -d ':' -f 1)
		echo "IP:$IP"

		COUNTRY=`geoiplookup $IP | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'`
		echo "COUNTRY:$COUNTRY"

		SUBNET_IP=`MF_GET_SUBNET $IP`
		echo "SUBNET_IP:$SUBNET_IP"

		# 检查是否为目标国家
		if [[ "$COUNTRY" != "CN" ]]; then

			# ss -n state syn-recv -o
			# 判断重试次数

			IP_PREFIX_STR=`MF_GET_PRESTR $IP`

			echo "IP_PREFIX_STR:$IP_PREFIX_STR"
			NUMS=`netstat -an|grep SYN_RECV | grep $IP_PREFIX_STR | wc -l`
			echo "NUMS:$NUMS"

			# 规则1 , 138.94.192 同网段下超过2个，大概率为攻击方
			if [[ "$NUMS" -gt 2 ]];then
				MF_BAN_DO $SUBNET_IP
			fi
		else
		    echo "IP $IP 来自 $COUNTRY，允许访问。"
		fi
	done
}


MF_T(){
	RUN_CMD_SYN_SENT
}

RUN_CMD_SYN_SENT(){
	netstat -an | grep tcp | while read line; do
		echo $line
		SRC_IP=$(echo "$line" | awk '{print $5}' | cut -d= -f2)
		echo "SRC_IP:$SRC_IP"

		# 获取IP地址
		IP=$(echo $SRC_IP | cut -d ':' -f 1)
		echo "IP:$IP"

		if [[ "$IP" == "0.0.0.0" ]];then
			continue
		fi

		if [[ "$IP" == "" ]];then
			continue
		fi

		# geoiplookup 23.94.85.238 | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'
		COUNTRY=`geoiplookup $IP | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'`
		echo "COUNTRY:$COUNTRY"

		SUBNET_IP=`MF_GET_SUBNET $IP`
		echo "SUBNET_IP:$SUBNET_IP"

		# 检查是否为目标国家
		if [[ "$COUNTRY" != "CN" ]]; then

			# ss -n state syn-recv -o
			# 判断重试次数

			IP_PREFIX_STR=`MF_GET_PRESTR $IP`

			# netstat -an|grep tcp | grep 23.94.85 | wc -l
			echo "IP_PREFIX_STR:$IP_PREFIX_STR"
			NUMS=`netstat -an|grep tcp | grep $IP_PREFIX_STR | wc -l`
			echo "NUMS:$NUMS"

			# 规则1 , 138.94.192 同网段下超过2个，大概率为攻击方
			if [[ "$NUMS" -gt 2 ]];then
				MF_BAN_DO $SUBNET_IP
			fi

		else

			IP_PREFIX_STR=`MF_GET_PRESTR $IP`

			echo "IP_PREFIX_STR:$IP_PREFIX_STR"
			NUMS=`netstat -an|grep tcp | grep $IP_PREFIX_STR | wc -l`
			echo "NUMS:$NUMS"

			# 国内连接数太多，IP封禁1分钟
			if [[ "$NUMS" -gt 5 ]];then
				MF_BAN_DO1 $SUBNET_IP
				echo "IP $IP 来自 $COUNTRY，连接数太多,IP封禁1分钟。"
			else
				echo "IP $IP 来自 $COUNTRY，允许访问。"
			fi
		fi
	done
}

RUN_CMD(){
	# 设置超时时间（秒）
	TIMEOUT=3

	# 设置禁止访问的时间（秒）
	BAN_TIME=300

	# 获取当前时间
	CURRENT_TIME=$(date +%s)

	# SYN_RECV攻击
	# RUN_CMD_SYN_RECV
	RUN_CMD_FOREACH
	
}

RUN_CMD_FOREACH(){

	# 记录开始时间（Unix 时间戳）
	start_time=$(date +%s)
	timeout=50  # 50s 超时

	while true; do

		# SYN_RECV攻击
		RUN_CMD_SYN_RECV

	    # 执行你的命令（示例：打印当前时间）
	    echo "[$(date '+%H:%M:%S')] 执行任务..."

	    # 检查是否超过 1 分钟
	    current_time=$(date +%s)
	    elapsed=$((current_time - start_time))
	    if [ "$elapsed" -ge "$timeout" ]; then
	        echo "已运行1分钟，退出循环。"
	        break
	    fi
	    # 暂停 2 秒
	    sleep 2
	done


	
	
}

MF_LOOK(){
	# netstat -an|grep tcp
	# netstat -an|grep SYN_RECV
	watch -n 1 'netstat -an|grep SYN_RECV'
	# watch -n 1 'netstat -an|grep TIME_WAIT'
	# watch -n 2 'netstat -an|grep tcp'
	# geoiplookup 138.94.195.6 | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'
	# geoiplookup 218.26.157.158 | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'
	
}

MF_LOOK2(){
	# watch -n 2 'netstat -an| grep tcp|grep -v "127.0.0.1" | grep -v "LISTEN"'
	watch -n 2 'netstat -an | grep tcp|grep -v "127.0.0.1" | grep -v "LISTEN" | tail -n +3 | sort -k3 -nr'
	# netstat -an | grep -v "127.0.0.1" | grep -v "LISTEN"  | awk 'NR<=2 {print; next} {print | "sort -k2 -nr"}'
	# watch -n 2 'netstat -an | grep tcp|grep -v "127.0.0.1" | grep -v "LISTEN" | tail -n +2 | sort -k2 -nr'
	# netstat -an | grep tcp|grep -v "127.0.0.1" | grep -v "LISTEN" | tail -n +3 | sort -k3 -nr
	# netstat -an | grep tcp | grep -v "127.0.0.1" | grep -v "LISTEN" | awk '{print $5}' | sort | uniq -c
}


MF_LOOK3(){
	# ss -n state syn-recv -o
	watch -n 1 'ss -n state syn-recv -o'
}

MF_LOOK4(){
	# ss -n state syn-recv -o
	watch -n 1 'mtsf i'
}

MF_LOOK5(){
	# ss -n state syn-recv -o
	watch -n 1 'mtsf look_simple'
}

MF_LOOK6(){
	ss -nto | grep ESTAB | awk '{if ($6 ~ /sec/) {split($6, a, "sec"); if (a[1] > 30) print $5, $6}}'
}

MF_LOOK_TIME(){
	netstat -tnop | grep SYN_RECV | awk '{print $5,$9}'
}

# 手动优化
MF_HANDLE_OP(){
	iptables -L -n
	iptables -A INPUT -s 138.94.40.0/24 -j DROP
	iptables -A INPUT -s 138.94.192.0/32 -j DROP
	iptables -A INPUT -s 138.94.193.0/32 -j DROP
}

# 简单配置优化
MF_SIMPLE_OPT(){
	iptables -A INPUT -p tcp --syn -m limit --limit 5/s -j ACCEPT
	iptables -A INPUT -p tcp --syn -j DROP
}

# 配置优化命令
MF_CONF_OPT(){
	ulimit_n=$(ulimit -n)
	echo $ulimit_n
	if [[ "$ulimit_n" -lt "65535" ]]; then
		ulimit -n 65535
		echo -e "${GREEN}ulimit -n 65535${CEND}"


		ROOT_SOFT_LIMIT="root soft nofile 65535"
		ROOT_HARD_LIMIT="root hard nofile 65535"

		if grep -q "^root soft nofile" /etc/security/limits.conf; then
		    # 如果已存在 soft nofile 配置，则替换
		    sed -i '/^root soft nofile/c\'"$ROOT_SOFT_LIMIT" /etc/security/limits.conf
		else
		    # 如果不存在，则追加
		    echo "$ROOT_SOFT_LIMIT" >> /etc/security/limits.conf
		fi

		if grep -q "^root hard nofile" /etc/security/limits.conf; then
		    # 如果已存在 soft nofile 配置，则替换
		    sed -i '/^root hard nofile/c\'"$ROOT_HARD_LIMIT" /etc/security/limits.conf
		else
		    # 如果不存在，则追加
		    echo "$ROOT_HARD_LIMIT" >> /etc/security/limits.conf
		fi

		# 定义要添加的配置
		SOFT_LIMIT="* soft nofile 65535"
		HARD_LIMIT="* hard nofile 65535"

		# 检查并更新 limits.conf
		if grep -q "^[*] soft nofile" /etc/security/limits.conf; then
		    # 如果已存在 soft nofile 配置，则替换
		    sed -i '/^[*] soft nofile/c\'"$SOFT_LIMIT" /etc/security/limits.conf
		else
		    # 如果不存在，则追加
		    echo "$SOFT_LIMIT" >> /etc/security/limits.conf
		fi

		if grep -q "^[*] hard nofile" /etc/security/limits.conf; then
		    # 如果已存在 hard nofile 配置，则替换
		    sed -i '/^[*] hard nofile/c\'"$HARD_LIMIT" /etc/security/limits.conf
		else
		    # 如果不存在，则追加
		    echo "$HARD_LIMIT" >> /etc/security/limits.conf
		fi

		# 输出完成信息
		echo "limits.conf 配置已更新："
		grep "^[*] .* nofile" /etc/security/limits.conf
		echo -e "${GREEN}cat /etc/security/limits.conf${CEND}"

	fi

	# 设置TCP优化参数
	echo "===== 开始优化TCP参数 ====="

	# 接收和发送缓冲区大小
	echo "设置接收和发送缓冲区大小..."
	FIND_NC_rmem_max=`cat /etc/sysctl.conf | grep net.core.rmem_max`
	if [ "$FIND_NC_rmem_max" == "" ];then
		echo 16777216 > /proc/sys/net/core/rmem_max
		echo "net.core.rmem_max = 16777216" >> /etc/sysctl.conf
	else
		echo "net.core.rmem_max exist!"
	fi

	FIND_NC_wmem_max=`cat /etc/sysctl.conf | grep net.core.wmem_max`
	if [ "$FIND_NC_wmem_max" == "" ];then
		echo 16777216 > /proc/sys/net/core/wmem_max
		echo "net.core.wmem_max = 16777216" >> /etc/sysctl.conf
	else
		echo "net.core.wmem_max exist!"
	fi

	FIND_NI_tcp_rmem=`cat /etc/sysctl.conf | grep net.ipv4.tcp_rmem`
	if [ "$FIND_NI_tcp_rmem" == "" ];then
		echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_rmem
		echo "net.ipv4.tcp_rmem = 4096 87380 16777216" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_rmem exist!"
	fi


	FIND_NI_tcp_wmem=`cat /etc/sysctl.conf | grep net.ipv4.tcp_wmem`
	if [ "$FIND_NI_tcp_wmem" == "" ];then
		echo "4096 87380 16777216" > /proc/sys/net/ipv4/tcp_wmem
		echo "net.ipv4.tcp_wmem = 4096 87380 16777216" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_wmem exist!"
	fi

	FIND_NI_tcp_fastopen=`cat /etc/sysctl.conf | grep net.ipv4.tcp_fastopen`
	if [ "$FIND_NI_tcp_fastopen" == "" ];then
		echo "3" > /proc/sys/net/ipv4/tcp_fastopen
		echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_fastopen exist!"
	fi

	# 启用TCP窗口缩放和选择性确认
	echo "启用TCP窗口缩放和选择性确认..."
	FIND_NI_tcp_window_scaling=`cat /etc/sysctl.conf | grep net.ipv4.tcp_window_scaling`
	if [ "$FIND_NI_tcp_window_scaling" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_window_scaling
		echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_window_scaling exist!"
	fi

	FIND_NI_tcp_sack=`cat /etc/sysctl.conf | grep net.ipv4.tcp_sack`
	if [ "$FIND_NI_tcp_sack" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_sack
		echo "net.ipv4.tcp_sack = 1" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_sack exist!"
	fi

	FIND_NI_tcp_dsack=`cat /etc/sysctl.conf | grep net.ipv4.tcp_dsack`
	if [ "$FIND_NI_tcp_dsack" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_dsack
		echo "net.ipv4.tcp_dsack = 1" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_dsack exist!"
	fi

	# 启用时间戳
	echo "启用时间戳..."
	FIND_NI_tcp_timestamps=`cat /etc/sysctl.conf | grep net.ipv4.tcp_timestamps`
	if [ "$FIND_NI_tcp_timestamps" == "" ];then
		echo 0 > /proc/sys/net/ipv4/tcp_timestamps
		echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_timestamps exist!"
	fi

	# 优化TIME-WAIT状态
	echo "优化TIME-WAIT状态..."
	FIND_NI_tcp_fin_timeout=`cat /etc/sysctl.conf | grep net.ipv4.tcp_fin_timeout`
	if [ "$FIND_NI_tcp_fin_timeout" == "" ];then
		echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout
		echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_fin_timeout exist!"
	fi

	echo "优化ip_local_port_range设置..."
	FIND_NI_ip_local_port_range=`cat /etc/sysctl.conf | grep net.ipv4.ip_local_port_range`
	if [ "$FIND_NI_ip_local_port_range" == "" ];then
		echo 1024 65000 > /proc/sys/net/ipv4/ip_local_port_range
		echo "net.ipv4.ip_local_port_range = 1024 65001" >> /etc/sysctl.conf
	else
		echo "net.ipv4.ip_local_port_range exist!"
	fi

	# 允许将TIME-WAIT【sockets】重新用于新的TCP连接
	FIND_NI_tcp_tw_reuse=`cat /etc/sysctl.conf | grep net.ipv4.tcp_tw_reuse`
	if [ "$FIND_NI_tcp_tw_reuse" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse
		echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_tw_reuse exist!"
	fi

	# 开启TCP连接中TIME-WAIT【sockets】的快速回收
	if [ -d /proc/sys/net/ipv4/tcp_tw_recycle ];then
		FIND_NI_tcp_tw_recycle=`cat /etc/sysctl.conf | grep net.ipv4.tcp_tw_recycle`
		if [ "$FIND_NI_tcp_tw_recycle" == "" ];then
			echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle
			echo "net.ipv4.tcp_tw_recycle = 1" >> /etc/sysctl.conf
		else
			echo "net.ipv4.tcp_tw_recycle exist!"
		fi
	fi

	# cat /proc/sys/net/ipv4/tcp_syn_retries

	FIND_NI_tcp_max_tw_buckets=`cat /etc/sysctl.conf | grep net.ipv4.tcp_max_tw_buckets`
	if [ "$FIND_NI_tcp_max_tw_buckets" == "" ];then
		echo 65535 > /proc/sys/net/ipv4/tcp_max_tw_buckets
		echo "net.ipv4.tcp_max_tw_buckets = 65535" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_max_tw_buckets exist!"
	fi

	# 增加连接队列长度
	echo "增加连接队列长度..."
	FIND_NI_tcp_max_syn_backlog=`cat /etc/sysctl.conf | grep net.ipv4.tcp_max_syn_backlog`
	if [ "$FIND_NI_tcp_max_syn_backlog" == "" ];then
		echo 65535 > /proc/sys/net/ipv4/tcp_max_syn_backlog
		echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_max_syn_backlog exist!"
	fi

	FIND_NC_somaxconn=`cat /etc/sysctl.conf | grep net.core.somaxconn`
	if [ "$FIND_NC_somaxconn" == "" ];then
		echo 65535 > /proc/sys/net/core/somaxconn
		echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
	else
		echo "net.core.somaxconn exist!"
	fi

	# 启用SYN Cookies
	echo "启用SYN Cookies..."
	FIND_NI_tcp_syncookies=`cat /etc/sysctl.conf | grep net.ipv4.tcp_syncookies`
	if [ "$FIND_NI_tcp_syncookies" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_syncookies
		echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_syncookies exist!"
	fi

	# 优化Keepalive参数
	echo "优化Keepalive参数..."
	FIND_NI_tcp_keepalive_time=`cat /etc/sysctl.conf | grep net.ipv4.tcp_keepalive_time`
	if [ "$FIND_NI_tcp_keepalive_time" == "" ];then
		echo 180 > /proc/sys/net/ipv4/tcp_keepalive_time
		echo "net.ipv4.tcp_keepalive_time = 180" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_keepalive_time exist!"
	fi

	FIND_NI_tcp_keepalive_intvl=`cat /etc/sysctl.conf | grep net.ipv4.tcp_keepalive_intvl`
	if [ "$FIND_NI_tcp_keepalive_intvl" == "" ];then
		echo 15 > /proc/sys/net/ipv4/tcp_keepalive_intvl
		echo "net.ipv4.tcp_keepalive_intvl = 15" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_keepalive_intvl exist!"
	fi

	FIND_NI_tcp_keepalive_probes=`cat /etc/sysctl.conf | grep net.ipv4.tcp_keepalive_probes`
	if [ "$FIND_NI_tcp_keepalive_probes" == "" ];then
		echo 3 > /proc/sys/net/ipv4/tcp_keepalive_probes
		echo "net.ipv4.tcp_keepalive_probes = 3" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_keepalive_probes exist!"
	fi

	echo "===== TCP参数优化完成 ====="

	FIND_NC_default_qdisc=`cat /etc/sysctl.conf | grep net.core.default_qdisc`
	if [ "$FIND_NC_default_qdisc" == "" ];then
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	else
		echo "net.core.tcp_congestion_control exist"
	fi

	FIND_NC_tcp_congestion_control=`cat /etc/sysctl.conf | grep net.ipv4.tcp_congestion_control`
	if [ "$FIND_NC_tcp_congestion_control" == "" ];then
		echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_congestion_control exist"
	fi
	echo "===== BBR配置完成 ====="
	sysctl -p


	FIND_IRQ=`which irqbalance`
	if [ "$FIND_IRQ" != "" ];then
		echo "Linux系统中用于优化中断请求分配的工具[irqbalance]存在"
	fi


	NET_ETH=`route -n|awk '/^0.0.0.0/ {print $8}' |uniq`
	ifconfig ${NET_ETH} mtu 9000
	echo "===启用巨帧（Jumbo Frames）[ifconfig ${NET_ETH} mtu 9000]==="

	cpu_num=`grep -c "processor" /proc/cpuinfo`

	# echo ${cpu_num} | tee /sys/class/net/${NET_ETH}/queues/rx-0/rps_cpus
	echo "===手动启用RPS[echo ${cpu_num} | tee /sys/class/net/${NET_ETH}/queues/rx-0/rps_cpus]==="
	# echo 32768 | tee /sys/class/net/${NET_ETH}/queues/rx-0/rps_flow_cnt
	echo "===手动启用RFS[echo 32768 | tee /sys/class/net/${NET_ETH}/queues/rx-0/rps_flow_cnt]==="
	echo "===查看当前接口的LRO状态[ethtool -k ${NET_ETH} | grep large-receive-offload]==="
	# ethtool -K ${NET_ETH} gro on
	echo "===手动设置接口队列长度[ethtool -K ${NET_ETH} gro on]==="
	# ethtool -K ${NET_ETH} lro on
	echo "===手动设置接口队列长度[ethtool -K ${NET_ETH} lro on]==="
	# ethtool -G ${NET_ETH} rx 4096 tx 4096
	echo "===手动设置接口队列长度[ethtool -G ${NET_ETH} rx 4096 tx 4096]==="
	
	echo -e "简单优化完成!"
}

MF_CONF_NET_MBPS(){
	NET_ETH=`route -n|awk '/^0.0.0.0/ {print $8}' |uniq`

	# 获取当前接收和发送的字节数
	RX_BYTES=$(cat /sys/class/net/$NET_ETH/statistics/rx_bytes)
	TX_BYTES=$(cat /sys/class/net/$NET_ETH/statistics/tx_bytes)

	# 等待 1 秒
	sleep 1

	# 获取 1 秒后的接收和发送字节数
	RX_BYTES_NEW=$(cat /sys/class/net/$NET_ETH/statistics/rx_bytes)
	TX_BYTES_NEW=$(cat /sys/class/net/$NET_ETH/statistics/tx_bytes)

	# 计算 1 秒内的接收和发送带宽（单位：字节/秒）
	RX_BW=$((RX_BYTES_NEW - RX_BYTES))
	TX_BW=$((TX_BYTES_NEW - TX_BYTES))

	# 转换为 Mbps（1 字节 = 8 位，1 Mbps = 1,000,000 位）
	RX_BW_MBPS=$((RX_BW * 8 / 1000000))
	TX_BW_MBPS=$((TX_BW * 8 / 1000000))

	# 总带宽使用率
	BYTES_T=$((TX_BW + TX_BW))
	KB_T=$((BYTES_T/1024))
	TOTAL_BW_MBPS=$((BYTES_T*8/1000000))
	echo "当前网络使用:${KB_T}KB/s - ${TOTAL_BW_MBPS}Mbps"
}

# TCP重传率
MF_TCP_RERADIO(){
	sent=$(netstat -s | awk '/segments sent out/ {print $1}')
	retrans=$(netstat -s | awk '/segments retransmitted/ {print $1}')
	if [ "$sent" -gt 0 ]; then
    retrans_rate=$(echo "scale=4; $retrans / $sent * 100" | bc)
	    echo "TCP Retransmission Rate: $retrans_rate%"
	else
	    echo "No data sent, cannot calculate retransmission rate."
	fi
}

MF_TCP_INFO(){
	# 获取本地端口范围
	read port_min port_max < /proc/sys/net/ipv4/ip_local_port_range
	port_count=$((port_max - port_min + 1))

	# 获取文件描述符限制
	file_max=$(cat /proc/sys/fs/file-max)
	ulimit_n=$(ulimit -n)
	fd_limit=$((file_max < ulimit_n ? file_max : ulimit_n))

	# 获取TCP内存限制（以页为单位，1页=4KB）
	read tcp_mem_min tcp_mem_pressure tcp_mem_max < /proc/sys/net/ipv4/tcp_mem
	tcp_mem_max_kb=$((tcp_mem_max * 4))
	tcp_mem_max_mb=$((tcp_mem_max_kb / 1024))

	# 计算最大TCP连接数
	max_connections=$((port_count < fd_limit ? port_count : fd_limit))

	# 输出结果
	echo "本地端口范围: $port_min - $port_max (可用端口: $port_count)"
	echo "文件描述符限制: $fd_limit"
	echo "TCP内存限制: $tcp_mem_max_mb MB"
	echo "最大TCP连接数: $max_connections"

	cur_max_connections=`cat /proc/net/tcp | wc -l`
	echo "当前TCP连接数: ${cur_max_connections} [cat /proc/net/tcp | wc -l]"
	cur_max_connections2=`netstat -an | grep tcp | wc -l`
	echo "当前TCP连接数[2]: ${cur_max_connections2} [netstat -an | grep tcp | wc -l]"

	cur_syn_recv=`netstat -an|grep SYN_RECV | wc -l`
	echo "当前TCP{SYN_RECV}连接数: ${cur_syn_recv} [netstat -an|grep SYN_RECV | wc -l]"

	current_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
	echo "当前TCP控制算法: ${current_algorithm}"

	sockstat=$(cat /proc/net/sockstat)
	# 提取关键信息
	sockets_used=$(echo "$sockstat" | grep 'sockets:' | awk '{print $3}')
	tcp_inuse=$(echo "$sockstat" | grep 'TCP:' | awk '{print $3}')
	tcp_mem=$(echo "$sockstat" | grep 'TCP:' | awk '{print $NF}')
	udp_inuse=$(echo "$sockstat" | grep 'UDP:' | awk '{print $3}')
	udp_mem=$(echo "$sockstat" | grep 'UDP:' | awk '{print $NF}')

	# 输出结果
	echo "-------------------------socket-------------------------"
	echo "总套接字数: $sockets_used"
	echo "TCP 连接数: $tcp_inuse"
	echo "TCP 内存占用: $((tcp_mem * 4)) KB"
	echo "UDP 连接数: $udp_inuse"
	echo "UDP 内存占用: $((udp_mem * 4)) KB"
	

	echo -e "${RED}ss -s${PLAIN}"
	ss -s
	iptables -L -n
}

MF_LOOK_SIMPLE(){
	# 获取本地端口范围
	read port_min port_max < /proc/sys/net/ipv4/ip_local_port_range
	port_count=$((port_max - port_min + 1))

	# 获取文件描述符限制
	file_max=$(cat /proc/sys/fs/file-max)
	ulimit_n=$(ulimit -n)
	fd_limit=$((file_max < ulimit_n ? file_max : ulimit_n))

	# 获取TCP内存限制（以页为单位，1页=4KB）
	read tcp_mem_min tcp_mem_pressure tcp_mem_max < /proc/sys/net/ipv4/tcp_mem
	tcp_mem_max_kb=$((tcp_mem_max * 4))
	tcp_mem_max_mb=$((tcp_mem_max_kb / 1024))

	# 计算最大TCP连接数
	max_connections=$((port_count < fd_limit ? port_count : fd_limit))

	# 输出结果
	echo "本地端口范围: $port_min - $port_max (可用端口: $port_count)"
	echo "文件描述符限制: $fd_limit"
	echo "TCP内存限制: $tcp_mem_max_mb MB"
	echo "最大TCP连接数: $max_connections"

	cur_max_connections=`cat /proc/net/tcp | wc -l`
	echo "当前TCP连接数: ${cur_max_connections} [cat /proc/net/tcp | wc -l]"
	cur_max_connections2=`netstat -an | grep tcp | wc -l`
	echo "当前TCP连接数[2]: ${cur_max_connections2} [netstat -an | grep tcp | wc -l]"

	cur_syn_recv=`netstat -an|grep SYN_RECV | wc -l`
	echo "当前TCP{SYN_RECV}连接数: ${cur_syn_recv} [netstat -an|grep SYN_RECV | wc -l]"

	current_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
	echo "当前TCP控制算法: ${current_algorithm}"
	MF_CONF_NET_MBPS
	MF_TCP_RERADIO

	sockstat=$(cat /proc/net/sockstat)
	# 提取关键信息
	sockets_used=$(echo "$sockstat" | grep 'sockets:' | awk '{print $3}')
	tcp_inuse=$(echo "$sockstat" | grep 'TCP:' | awk '{print $3}')
	tcp_mem=$(echo "$sockstat" | grep 'TCP:' | awk '{print $NF}')
	udp_inuse=$(echo "$sockstat" | grep 'UDP:' | awk '{print $3}')
	udp_mem=$(echo "$sockstat" | grep 'UDP:' | awk '{print $NF}')

	# 输出结果
	echo "-------------------------socket-------------------------"
	echo "总套接字数: $sockets_used"
	echo "TCP 连接数: $tcp_inuse"
	echo "TCP 内存占用: $((tcp_mem * 4)) KB"
	echo "UDP 连接数: $udp_inuse"
	echo "UDP 内存占用: $((udp_mem * 4)) KB"

	echo "====================== 系统基本信息 ======================"
	echo "主机名称: $(hostname)"
	echo "操作系统: $(cat /etc/os-release | grep "PRETTY_NAME" | cut -d '"' -f 2)"
	echo "内核版本: $(uname -r)"
	echo "系统时间: $(date)"
	echo "运行时间: $(uptime -p)"

	echo "======================= 防火墙信息 ======================="
	iptables -L -n

}

MF_UPDATE(){
	if [ -f /usr/bin/mtsf ];then
		rm -rf /usr/bin/mtsf
	fi
	
	bash <(curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/install.sh)

	MF_TCP_INFO
}

MF_CRON_ADD(){
	FIND_MTSF_CRON=`cat /var/spool/cron/crontabs/root | grep "mtsf run"`

	if [ "$FIND_MTSF_CRON" != "" ];then
		echo "已经在计划任务里【${FIND_MTSF_CRON}】"
	else
		echo  "* * * * * /usr/bin/mtsf run > /tmp/mtsf.log"  >> /var/spool/cron/crontabs/root
		echo -e "${BLUE}添加mtsf任务成功!${CEND}"
	fi
	chmod 600 /var/spool/cron/crontabs/root

	# 定义要添加的计划任务
	# cron_job="* * * * * /usr/bin/mtsf run > /tmp/mtsf.log"
	# 将计划任务写入 /etc/cron.d/mtsf_cron
	# echo "$cron_job" | tee /etc/cron.d/mtsf_cron > /dev/null

	# 检查
	# grep CRON /var/log/syslog
	# grep CRON /var/log/messages
	# systemctl enable cron
	# systemctl restart cron
	# systemctl status cron
	
}

MF_CRON_DELETE(){
	FIND_MTSF_CRON=`cat /var/spool/cron/crontabs/root | grep "mtsf run"`
	if [ "$FIND_MTSF_CRON" == "" ];then
		echo -e "${BLUE}已经删除mtsf任务!${CEND}"
		return
	fi


	# rm -rf /etc/cron.d/mtsf_cron
	# 要删除的命令
	TARGET_CMD="mtsf run"
	# 临时文件
	TEMP_FILE=$(mktemp)
	# 导出当前任务到临时文件
	crontab -l > "$TEMP_FILE"
	# 删除目标命令
	sed -i "\|$TARGET_CMD|d" "$TEMP_FILE"
	# 重新导入任务
	crontab "$TEMP_FILE"
	# 清理临时文件
	rm -f "$TEMP_FILE"
	# echo "TEMP_FILE:$TEMP_FILE"
	echo -e "${BLUE}删除mtsf任务成功!${CEND}"
}

MF_CRON_LOG(){
	cat /tmp/mtsf.log
}

MF_TO_CUBIC(){
	# 检查当前 TCP 拥塞控制算法
	current_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
	echo "当前 TCP 拥塞控制算法: $current_algorithm"

	# 如果当前算法是 BBR，则替换为 CUBIC
	if [[ "$current_algorithm" == "bbr" ]]; then
	    echo "正在将 TCP 拥塞控制算法从 BBR 替换为 CUBIC..."

	    # 临时修改为 CUBIC
	    sysctl -w net.ipv4.tcp_congestion_control=cubic

	    old_setting="net.ipv4.tcp_congestion_control=bbr"
		new_setting="net.ipv4.tcp_congestion_control=cubic"

	    # 永久修改（写入配置文件）
	    if ! grep -q "net.ipv4.tcp_congestion_control=cubic" /etc/sysctl.conf; then
	        sed -i "s/^$old_setting/$new_setting/" /etc/sysctl.conf
	    fi

	    # 重新加载配置
	    sysctl -p
	    echo "TCP 拥塞控制算法已成功替换为 CUBIC。"
	else
	    echo "当前算法不是 BBR，无需替换。"
	fi

	# 验证修改结果
	echo "修改后的 TCP 拥塞控制算法："
	sysctl net.ipv4.tcp_congestion_control
}

MF_TO_BBR(){
	# 检查当前 TCP 拥塞控制算法
	current_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
	echo "当前 TCP 拥塞控制算法: $current_algorithm"

	# 如果当前算法是 BBR，则替换为 CUBIC
	if [[ "$current_algorithm" == "cubic" ]]; then
	    echo "正在将 TCP 拥塞控制算法从 BBR 替换为 CUBIC..."

	    # 临时修改为 CUBIC
	    sysctl -w net.ipv4.tcp_congestion_control=bbr
	    old_setting="net.ipv4.tcp_congestion_control=cubic"
		new_setting="net.ipv4.tcp_congestion_control=bbr"
	    # 永久修改（写入配置文件）
	    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
	        sed -i "s/^$old_setting/$new_setting/" /etc/sysctl.conf
	    fi

	    # 重新加载配置
	    sysctl -p
	    echo "TCP 拥塞控制算法已成功替换为BBR"
	else
	    echo "当前算法不是CUBIC无需替换"
	fi

	# 验证修改结果
	echo "修改后的 TCP 拥塞控制算法："
	sysctl net.ipv4.tcp_congestion_control
}

MF_HELP(){
	echo "mtsf run|r            -> 简单防护"
	echo "mtsf look|l           -> 查看网络SYN_RECV状态"
	echo "mtsf look_simple      -> 查看网络综合信息"
	echo "mtsf l2               -> 查看网络状态"
	echo "mtsf l3               -> 查看ss -s状态"
	echo "mtsf l4               -> 监控网络综合信息【没有带宽信息】"
	echo "mtsf l5               -> 监控网络综合信息【有带宽信息】"
	echo "mtsf info|i           -> 查看网络综合信息"
	echo "mtsf update|u         -> 更新脚本"
	echo "mtsf opt|o            -> 简单优化系统配置"
	echo "mtsf cron_add         -> 添加计划任务【简单防护】"
	echo "mtsf cron_del         -> 删除计划任务【简单防护】"
	echo "mtsf log              -> 简单防护日志"
	echo "mtsf net              -> 网络带宽信息"
	echo "mtsf to_cubic         -> bbr替换成cubic"
	echo "mtsf to_bbr           -> cubic替换成bbr"
	echo "mtsf version|v        -> 版本信息"
	echo "mtsf ip_stats         -> 查看网络IP连接统计"
	echo "mtsf chinese_gc       -> 中文乱码解决"
	echo "mtsf t                -> 测试脚本"
	echo "mtsf iptable_look     -> 防火墙查看"
}

MF_IP_STATS(){
	netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr
}


# 解决中文乱码
MF_RChineseGC(){
	if [ ! -f /usr/sbin/locale-gen ];then
		apt install -y locales
		sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen
		locale-gen en_US.UTF-8
		locale-gen zh_CN.UTF-8
		localedef -v -c -i en_US -f UTF-8 en_US.UTF-8 > /dev/null 2>&1
		update-locale LANG=en_US.UTF-8
	else
		locale-gen en_US.UTF-8
		locale-gen zh_CN.UTF-8
		localedef -v -c -i en_US -f UTF-8 en_US.UTF-8 > /dev/null 2>&1
	fi
}

case "$1" in
    "run" | "r") RUN_CMD ;;
    "look" | "l") MF_LOOK ;;
	"look_simple") MF_LOOK_SIMPLE ;;
	"l2") MF_LOOK2 ;;
	"l3") MF_LOOK3 ;;
	"l4") MF_LOOK4 ;;
	"l4") MF_LOOK4 ;;
	"l5") MF_LOOK5 ;;
	"info" | "i") MF_TCP_INFO;;
	"update" | "u") MF_UPDATE;;
	"opt" | "o") MF_CONF_OPT;;
	"cron_add" ) MF_CRON_ADD;;
	"cron_del" ) MF_CRON_DELETE;;
	"log" ) MF_CRON_LOG;;
	"net" ) MF_CONF_NET_MBPS;;
	"to_cubic" ) MF_TO_CUBIC;;
	"to_bbr" ) MF_TO_BBR;;
	"version" | "v") MF_VERSION;;
	"ip_stats") MF_IP_STATS ;;
	"chinese_gc") MF_RChineseGC ;;
	"t" ) MF_T;;
	"iptable_look") iptables -L -n;;
	*) MF_HELP;;
esac



