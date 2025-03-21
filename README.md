# shell

各种操作和维护脚本

### tcp_syn_flood (tcp洪水防护)

-  安装
```
bash <(curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/install.sh)
```

- 卸载

```
bash <(curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/uninstall.sh)
```

- 命令
```
mtsf look|l     -> 查看SYN_RECV连接
mtsf run|r      -> 执行防护命令
mtsf info|i     -> 查看tcp相关信息
mtsf opt|o      -> 简单的配置优化
mtsf update|u   -> 更新到最新版
mtsf cron_add   -> 添加到计划任务
mtsf cron_del   -> 从计划任务删除
```
