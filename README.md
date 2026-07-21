# MikroTik RouterOS Patch
[![Patch Mikrotik RouterOS](https://github.com/elseif/MikroTikPatch/actions/workflows/main.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/main.yml)
![Cloud Status](https://img.shields.io/endpoint?url=https://mikrotik.ltd/status/cloud)

[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)


>## ⚠️ 重要声明
>
>**此项目及工具仅供测试用途。使用风险自负。生产环境请使用官方授权版本。**

## 🏗️ 架构支持
### x86 / arm64 （本项目）
- **主页：** https://mikrotik.ltd/ 
- **演示：** https://demo.mikrotik.ltd/
- **授权： 安装option.npk后将自动授予最高级别许可证。**
- **授权BOT：** https://t.me/ROS_Keygen_Bot
- **Docker：** `docker run -d --privileged --name chr ghcr.io/elseif/

### arm64, arm, mipsbe, mmips, ppc, smips, x86 
- **主页：** https://routeros.ltd/
- **授权： 需要赞助**，*CHR版本(x86/Arm64)支持在线直接获取授权*
- **功能：** 支持在线自定义制作品牌包


## 🔧 功能指南
以下功能均需先安装 `option.npk` 包。
### 1. 启用容器模式（无需物理重启）
```bash
# 步骤 1：启用容器模式
/system/device-mode/update container=yes
# 步骤 2：强制重启（在新终端中执行）
/system/shell cmd="reboot -f"
```
### 2. Shell 访问
#### A. 通过终端
```bash
/system/shell
# 或简写
/sh
```
#### B. 通过 SSH / Telnet
```bash
# 用户名: devel
# 密码: 与 admin 密码相同
ssh devel@<router-ip>
```
### 3. x86 架构：CHR ↔ x86 模式切换

```bash
# 进入 shell 后执行
keygen chr   # 切换为 CHR 模式
keygen x86   # 切换为 x86 模式
```
### 4. 开机自动运行脚本

1. 创建或编辑 `/rw/disk/rc.local` 文件
2. 写入脚本内容，例如：

```bash
#!/bin/sh
# This script will be executed *before* RouterOS *loader* start.
# You can put your own initialization stuff in here
echo "Hello, world!"
```

3. 开机启动时将看到输出：`Starting rc.local...`
4. 启动后查看输出：

```bash
# 进入 shell
cat /ram/startup.catlog | grep 'Hello'
```

---

## ☁️ 云服务功能

| 功能 | 命令 |
|------|------|
| 在线升级 | `system/package/update/install` |
| 动态域名 | `ip/cloud/set ddns-enabled=yes` |
| 云备份 | `/system/backup/cloud/upload-file action=create-and-upload password=any` |
| 网络检测 | `/interface/detect-internet/set detect-interface-list=all` |

---

## 📚 相关资源

- [MikroTik 官方文档](https://manual.mikrotik.com/)
- [Telegram 群组](https://t.me/+99Mw06p3K7NlMmNl)
- [GitHub 源码](https://github.com/elseif/MikroTikPatch)


---
## 💖 感谢赞助
[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")
[DartNode(aff)](https://dartnode.com?aff=SnazzyLobster067)  | [ZMTO(aff)](https://console.zmto.com/?affid=1588) | [Vultr(aff)](https://www.vultr.com/?ref=9807160-9J)














