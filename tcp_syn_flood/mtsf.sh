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


RUN_CMD(){
	# 设置超时时间（秒）
	TIMEOUT=3

	# 设置禁止访问的时间（秒）
	BAN_TIME=300

	# 获取当前时间
	CURRENT_TIME=$(date +%s)

	# 获取所有 SYN_RECV 状态的连接
	conntrack -L -p tcp --state SYN_RECV | while read line; do
		if [[ "$line" =~ "conntrack-tools" ]];then
			echo $line
			continue
		fi

	    # 提取连接信息
	    SRC_IP=$(echo $line | awk '{print $5}' | cut -d= -f2)
	    DST_IP=$(echo $line | awk '{print $6}' | cut -d= -f2)
	    SRC_PORT=$(echo $line | awk '{print $8}' | cut -d= -f2)
	    DST_PORT=$(echo $line | awk '{print $9}' | cut -d= -f2)
	    echo "line:$line"
	    echo "SRC_IP:$SRC_IP,DST_IP:$DST_IP,SRC_PORT:$SRC_PORT,DST_PORT:$DST_PORT"

	    # 获取连接的创建时间
	    CREATED=$(echo $line | grep -oP 'start=\K[0-9]+')

	    # 计算连接持续时间
	    DURATION=$((CURRENT_TIME - CREATED))

	    echo "DURATION:$DURATION"

	    # 如果连接持续时间超过超时时间，则禁止该IP
	    if [ $DURATION -ge $TIMEOUT ]; then
	        echo "Banning $SRC_IP for $BAN_TIME seconds due to SYN_RECV timeout."
	        iptables -A INPUT -s $SRC_IP -j DROP

	        # 设置一个定时任务，5分钟后解禁该IP
	        (
	            sleep $BAN_TIME
	            iptables -D INPUT -s $SRC_IP -j DROP
	            echo "Unbanned $SRC_IP after $BAN_TIME seconds."
	        ) &
	    fi
	done
}

MF_LOOK(){
	watch -n 1 'netstat -an|grep SYN_RECV'
}

MF_LOOK_SS(){
	ss -n state syn-recv -o
}

MF_LOOK_TIME(){
	netstat -tnop | grep SYN_RECV | awk '{print $5,$9}'
}

# 手动优化
MF_HANDLE_OP(){
	iptables -A INPUT -s 138.94.40.0/24 -j DROP
}

# 简单配置优化
MF_SIMPLE_OP(){
	iptables -A INPUT -p tcp --syn -m limit --limit 5/s -j ACCEPT
	iptables -A INPUT -p tcp --syn -j DROP
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

	echo -e "${RED}ss -s${PLAIN}"
	ss -s 
}

MF_UPDATE(){
	if [ -f /usr/bin/mtsf ];then
		rm -rf /usr/bin/mtsf
	fi
	curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/install.sh | sh
}

case "$1" in
    "run") RUN_CMD ;;
    "look") MF_LOOK ;;
	"info") MF_TCP_INFO;;
	"update") MF_UPDATE;;
    *) iptables -L ;;
esac



