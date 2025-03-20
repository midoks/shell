#!/bin/bash

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
	echo "mtsf - 0.0.1"
}
RUN_CMD(){
	# 设置超时时间（秒）
	TIMEOUT=3

	# 设置禁止访问的时间（秒）
	BAN_TIME=300

	# 获取当前时间
	CURRENT_TIME=$(date +%s)

	# 获取所有 SYN_RECV 状态的连接
	netstat -an | grep SYN_RECV | while read line; do
		echo $line
		SRC_IP=$(echo "$line" | awk '{print $5}' | cut -d= -f2)

		echo "SRC_IP:$SRC_IP"
		# if [[ "$line" =~ "conntrack-tools" ]];then
		# 	echo $line
		# 	continue
		# fi

	    # # 提取连接信息
	    # SRC_IP=$(echo $line | awk '{print $5}' | cut -d= -f2)
	    # DST_IP=$(echo $line | awk '{print $6}' | cut -d= -f2)
	    # SRC_PORT=$(echo $line | awk '{print $8}' | cut -d= -f2)
	    # DST_PORT=$(echo $line | awk '{print $9}' | cut -d= -f2)
	    # echo "line:$line"
	    # echo "SRC_IP:$SRC_IP,DST_IP:$DST_IP,SRC_PORT:$SRC_PORT,DST_PORT:$DST_PORT"

	    # # 获取连接的创建时间
	    # CREATED=$(echo $line | grep -oP 'start=\K[0-9]+')

	    # # 计算连接持续时间
	    # DURATION=$((CURRENT_TIME - CREATED))

	    # echo "DURATION:$DURATION"

	    # # 如果连接持续时间超过超时时间，则禁止该IP
	    # if [ $DURATION -ge $TIMEOUT ]; then
	    #     echo "Banning $SRC_IP for $BAN_TIME seconds due to SYN_RECV timeout."
	    #     iptables -A INPUT -s $SRC_IP -j DROP

	    #     # 设置一个定时任务，5分钟后解禁该IP
	    #     (
	    #         sleep $BAN_TIME
	    #         iptables -D INPUT -s $SRC_IP -j DROP
	    #         echo "Unbanned $SRC_IP after $BAN_TIME seconds."
	    #     ) &
	    # fi
	done
}

MF_LOOK(){
	# netstat -an|grep SYN_RECV
	watch -n 1 'netstat -an|grep SYN_RECV'
	# geoiplookup 138.94.195.6 | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'
	# geoiplookup 218.26.157.158 | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'
	
}

MF_LOOK_SS(){
	# ss -n state syn-recv -o
	watch -n 1 'ss -n state syn-recv -o'
}

MF_LOOK_TIME(){
	netstat -tnop | grep SYN_RECV | awk '{print $5,$9}'
}

# 手动优化
MF_HANDLE_OP(){
	iptables -A INPUT -s 138.94.40.0/24 -j DROP
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

	# 启用时间戳
	echo "启用时间戳..."
	FIND_NI_tcp_timestamps=`cat /etc/sysctl.conf | grep net.ipv4.tcp_timestamps`
	if [ "$FIND_NI_tcp_timestamps" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_timestamps
		echo "net.ipv4.tcp_timestamps = 1" >> /etc/sysctl.conf
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

	FIND_NI_tcp_tw_reuse=`cat /etc/sysctl.conf | grep net.ipv4.tcp_tw_reuse`
	if [ "$FIND_NI_tcp_tw_reuse" == "" ];then
		echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse
		echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_tw_reuse exist!"
	fi

	if [ -d /proc/sys/net/ipv4/tcp_tw_recycle ];then
		echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle
	fi

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
		echo 600 > /proc/sys/net/ipv4/tcp_keepalive_time
		echo "net.ipv4.tcp_keepalive_time = 600" >> /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_keepalive_time exist!"
	fi

	FIND_NI_tcp_keepalive_intvl=`cat /etc/sysctl.conf | grep net.ipv4.tcp_keepalive_intvl`
	if [ "$FIND_NI_tcp_keepalive_intvl" == "" ];then
		echo 30 > /proc/sys/net/ipv4/tcp_keepalive_intvl
		echo "net.ipv4.tcp_keepalive_intvl = 30" >> /etc/sysctl.conf
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

	echo -e "done!"
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
	echo "-------------------------socket-------------------------"

	echo -e "${RED}ss -s${PLAIN}"
	ss -s 
}

MF_UPDATE(){
	if [ -f /usr/bin/mtsf ];then
		rm -rf /usr/bin/mtsf
	fi
	curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/install.sh | sh
	MF_TCP_INFO
	MF_VERSION
}

case "$1" in
    "run" | "r") RUN_CMD ;;
    "look" | "l") MF_LOOK ;;
	"info" | "i") MF_TCP_INFO;;
	"update" | "u") MF_UPDATE;;
	"opt" | "o") MF_CONF_OPT;;
	"version" | "v") MF_VERSION;;
    *) iptables -L ;;
esac



