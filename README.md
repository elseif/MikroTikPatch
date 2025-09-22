[![Patch Mikrotik RouterOS 6.x](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_6.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_6.yml)
[![Patch Mikrotik RouterOS 7.x](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_7.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_7.yml)

### 感谢赞助
[DartNode(aff)](https://dartnode.com?aff=SnazzyLobster067) | [ZMTO(aff)](https://console.zmto.com/?affid=1588) | [Vultr(aff)](https://www.vultr.com/?ref=9807160-9J)

# MikroTik RouterOS Patch  [[English](README_EN.md)]
[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)

### [[Discord](https://discord.gg/keV6MWQFtX)] [[Telegram](https://t.me/mikrotikpatch)] [[Keygen(Telegram Bot)](https://t.me/ROS_Keygen_Bot)]

支持:在线更新、在线授权、云备份、DDNS

![Cloud Status](https://img.shields.io/endpoint?url=https://mikrotik.ltd/status/cloud)
![VPS Status](https://img.shields.io/endpoint?url=https://mikrotik.ltd/status/dartnode)

*如果云服务或部署云服务的虚拟主机都不在线，那么在线更新、在线授权、云备份、DDNS以及ROS_Keygen_Bot都暂时不能使用*

### 从7.19.4和7.20beta8开始，安装option包以后会自动激活授权，如果有rc.local文件，会自动加载运行。
```mermaid
graph TD
    A[启动] --> B[检查 keygen 文件是否存在 ]
    B -->|是| C[fork 执行 keygen]
    B -->|否| D[检查 rc.local 文件是否存在]
    C --> D
    D -->|是| E[fork 执行 /bin/sh rc.local]
    D -->|否| F[启动服务]
    E --> F
```
![](image/install.png)
![](image/routeros.png)

### x86模式授权许可
![](image/x86.png)
### x86模式在线授权(v6.x)
![](image/renew_v6.png)
### Chr模式在线授权
![](image/renew.png)
### Chr模式授权许可
![](image/chr.png)

![](image/arm.png)
![](image/mips.png)

## 如何使用Shell
    安装 option-{version}.npk 包
    telnet到RouterOS,用户名devel,密码与admin的密码相同
    要使用devel用户名登录必须安装option-{version}.npk包，且启用。
## 如何授权许可
    进入shell
    运行 keygen
    参考上图。
    Chr镜像支持在线授权许可
## 如何使用Python
    安装 python3-{version}.npk 包
    telnet到RouterOS,用户名devel,密码与admin的密码相同
    运行 python -V
### npk.py
    对npk文件进行解包，修改，创建，签名和验证
### patch.py
    替换公钥并签名
    
## 所有的修补操作都自动运行在[Github Action](https://github.com/elseif/MikroTikPatch/blob/main/.github/workflows/)。













