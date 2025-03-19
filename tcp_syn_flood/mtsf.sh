#!/bin/bash

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

case "$1" in
    "run") RUN_CMD ;;
    'look') MF_LOOK ;;
    *) iptables -L ;;
esac



