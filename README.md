# shell

各种操作和维护脚本

### tcp_syn_flood (tcp洪水防护)

-  安装
```
curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/install.sh| sh
```

- 卸载

```
curl -fsSL https://raw.githubusercontent.com/midoks/shell/refs/heads/main/tcp_syn_flood/uninstall.sh| sh
```

- 命令
```
mtsf look|l     -> 查看SYN_RECV连接
mtsf run|r      -> 执行防护命令
mtsf info|i     -> 查看tcp相关信息
mtsf opt|o 	    -> 简单的配置优化
mtsf update|u   -> 更新到最新版
```
