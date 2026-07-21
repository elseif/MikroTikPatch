# MikroTik RouterOS Patch
[![Patch Mikrotik RouterOS](https://github.com/elseif/MikroTikPatch/actions/workflows/main.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/main.yml)
![Cloud Status](https://img.shields.io/endpoint?url=https://mikrotik.ltd/status/cloud)

[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)

**English** | [中文](./README_CN.md)

> ## ⚠️ Important Notice
>
> **This project and its tools are for testing purposes only. Use at your own risk. Please use the officially licensed version for production environments.**

## 🏗️ Architecture Support
### x86 / arm64 (This Project)
- **Homepage:** https://mikrotik.ltd/ 
- **Demo:** https://demo.mikrotik.ltd/
- **License: Installing `option.npk` will automatically grant the highest-level license.**
- **License Bot:** https://t.me/ROS_Keygen_Bot
- **Docker：** `docker run -d --privileged --name chr ghcr.io/elseif/chr:latest`

### arm64, arm, mipsbe, mmips, ppc, smips, x86 
- **Homepage:** https://routeros.ltd/
- **License: Sponsorship required.** *CHR versions (x86/Arm64) support online direct licensing.*
- **Features:** Supports online custom branded package creation.
---

## 🔧 Feature Guide
All features below require the `option.npk` package to be installed first.
### 1. Enable Container Mode (No Physical Reboot Required)
```bash
# Step 1: Enable container mode
/system/device-mode/update container=yes
# Step 2: Force reboot (execute in a new terminal)
/system/shell cmd="reboot -f"
```
### 2. Shell Access
#### A. Via Terminal
```bash
/system/shell
# or shorthand
/sh
```
#### B. Via SSH / Telnet
```bash
# Username: devel
# Password: Same as the admin password
ssh devel@<router-ip>
```
### 3.  x86 Architecture: CHR ↔ x86 Mode Switch

```bash
# Execute after entering shell
keygen chr   # Switch to CHR mode
keygen x86   # Switch to x86 mode
```
### 4. Boot Auto-Run Script

1. Create or edit the `/rw/disk/rc.local` file.
2. Write your script content, for example：

```bash
#!/bin/sh
# This script will be executed *before* RouterOS *loader* start.
# You can put your own initialization stuff in here
echo "Hello, world!"
```

3. You will see the output during boot: `Starting rc.local...`
4. After boot, check the output:

```bash
# Enter shell
cat /ram/startup.catlog | grep 'Hello'
```

---

## ☁️ Cloud Services

| Feature | Command |
|------|------|
| Online Upgrade | `system/package/update/install` |
| Dynamic DNS | `ip/cloud/set ddns-enabled=yes` |
| Cloud Backup | `/system/backup/cloud/upload-file action=create-and-upload password=any` |
| Internet Detection | `/interface/detect-internet/set detect-interface-list=all` |

---

## 📚 Resources

- [MikroTik Official Documentation](https://manual.mikrotik.com/)
- [Telegram Group](https://t.me/+99Mw06p3K7NlMmNl)
- [GitHub Source Code](https://github.com/elseif/MikroTikPatch)


---
## 💖 Sponsors
[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")
[DartNode(aff)](https://dartnode.com?aff=SnazzyLobster067)  | [ZMTO(aff)](https://console.zmto.com/?affid=1588) | [Vultr(aff)](https://www.vultr.com/?ref=9807160-9J)














