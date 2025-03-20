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
mtsf look   -> 查看SYN_RECV连接
mtsf run 	-> 执行防护命令
mtsf info 	-> 查看tcp相关信息
```
