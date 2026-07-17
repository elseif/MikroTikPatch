# MikroTik RouterOS Patch  [[English](README_EN.md)]
[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)


[![Patch Mikrotik RouterOS](https://github.com/elseif/MikroTikPatch/actions/workflows/main.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/main.yml)![Cloud Status](https://img.shields.io/endpoint?url=https://mikrotik.ltd/status/cloud)

## ⚠️ 重要声明

**此项目及工具仅供测试用途。使用风险自负。生产环境请使用官方授权版本。**

## 架构：x86、arm64 
- **主页：** https://mikrotik.ltd/ 
- **演示：** https://demo.mikrotik.ltd/
- **授权：** 安装OPTION.NPK后将自动授予最高级别许可证。
- **源代码：** https://github.com/elseif/MikroTikPatch
- **授权BOT：** https://t.me/ROS_Keygen_Bot
- **Docker：** `docker pull ghcr.io/elseif/chr:latest`

## 架构：arm64, arm, mipsbe, mmips, ppc, smips, x86 
- **主页：** https://routeros.ltd/
- **授权：** 需要赞助，CHR版本(x86/Arm64支持在线直接获取授权)。
- **功能：** 支持在线自定义制作品牌包


## 支持的云功能
| 功能 | 命令 |
|------|------|
| 在线升级 | `system/package/update/install` |
| DDNS | `ip/cloud/set ddns-enabled=yes` |
| 云备份 | `/system/backup/cloud/upload-file action=create-and-upload password=any` |

## 启用容器模式（无需物理重启）
1. 安装 `option.npk` 包。
2. 打开终端执行：`system/device-mode/update container=yes`
3. 打开新终端执行：`system/shell cmd="reboot -f"`

### 更多关于RouterOS的信息请查看: https://manual.mikrotik.com/

### 感谢赞助
[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=dbf6ed365068&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)
[DartNode(aff)](https://dartnode.com?aff=SnazzyLobster067)  | [ZMTO(aff)](https://console.zmto.com/?affid=1588) | [Vultr(aff)](https://www.vultr.com/?ref=9807160-9J)
[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")













