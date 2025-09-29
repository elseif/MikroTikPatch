#!/bin/bash
set -e
_ask() {
	local _redo=0

	read resp
	case "$resp" in
	!)	echo "Type 'exit' to return to setup."
		sh
		_redo=1
		;;
	!*)	eval "${resp#?}"
		_redo=1
		;;
	esac
	return $_redo
}
ask() {
	local _question="$1" _default="$2"
	while :; do
		printf %s "$_question "
		[ -z "$_default" ] || printf "[%s] " "$_default"
		_ask && : ${resp:=$_default} && break
	done
}
ask_until() {
	resp=
	while [ -z "$resp" ] ; do
		ask "$1" "$2"
	done
}
yesno() {
	case $1 in
	[Yy]) return 0;;
	esac
	return 1
}
ask_yesno() {
	while true; do
		ask "$1" "$2"
		case "$resp" in
			Y|y|N|n) break;;
		esac
	done
	yesno "$resp"
}


select_language() {
    while true; do
        echo "Select your language:"
        echo "1. English"
        echo "2. 简体中文"
        ask_until "Please choose an option" "1"
        case $resp in
            1) 
                MSG_ARCH="Arch:"
                MSG_BOOTMODE="BootMode:"
                MSG_STORAGE_DEVICE="Input storage device name:"
                MSG_ADDRESS="Input IP address:"
                MSG_GATEWAY="Input gateway:"
                MSG_DNS="Input domain name server:"
                MSG_SELECT_VERSION="Select the version you want to install:"
                MSG_STABLE="stable (v7)"
                MSG_TEST="testing (v7)"
                MSG_LTS="long-term (v6)"
                MSG_STABLE6="stable (v6)"
                MSG_PLEASE_CHOOSE="Please choose an option:"
                MSG_UNSUPPORTED_ARCH="Error: Unsupported architecture: "
                MSG_INVALID_OPTION="Error: Invalid option!"
                MSG_ARM64_NOT_SUPPORT_V6="arm64 does not support v6 version for now."
                MSG_SELECTED_VERSION="Selected version:"
                MSG_FILE_DOWNLOAD="Download file: "
                MSG_DOWNLOAD_ERROR="Error: No wget nor curl is installed. Cannot download."
                MSG_EXTRACT_ERROR="Error: No unzip nor gunzip is installed. Cannot uncompress."
                MSG_DOWNLOAD_FAILED="Error: Download failed!"
                MSG_OPERATION_ABORTED="Error: Operation aborted."
                MSG_WARNING="Warn: All data on /dev/%s will be lost!"
                MSG_REBOOTING="Ok, rebooting..."
                MSG_ADMIN_PASSWORD="admin password:"
                MSG_MANUAL_PASS_CHOICE="Do you want to enter a password manually? (y/N): "
                MSG_ENTER_NEW_PASS="Enter new password: "
                MSG_PASS_EMPTY="Password cannot be empty, please try again."
                MSG_ERROR_MOUNT="Error: Failed to mount partition"
                MSG_ERROR_LOOP="Error: Failed to setup loop device"
                MSG_AUTO_RUN_FILE_CREATED="autorun.scr file created."
                MSG_AUTO_RUN_FILE_NOT_CREATED="Warn: autorun.scr file create failed"
                MSG_CONFIRM_CONTINUE="Do you want to continue? [y/n]"
                ;;
            2) 
                MSG_ARCH="CPU架构:"
                MSG_BOOTMODE="引导模式:"
                MSG_STORAGE_DEVICE="输入存储设备名称:"
                MSG_ADDRESS="输入IP地址:"
                MSG_GATEWAY="输入网关地址:"
                MSG_DNS="输入DNS服务器:"
                MSG_SELECT_VERSION="请选择您要安装的版本:"
                MSG_STABLE="稳定版 (v7)"
                MSG_TEST="测试版 (v7)"
                MSG_LTS="长期支持版 (v6)"
                MSG_STABLE6="稳定版 (v6)"
                MSG_PLEASE_CHOOSE="请选择一个选项:"
                MSG_UNSUPPORTED_ARCH="错误: 不支持的架构: "
                MSG_INVALID_OPTION="错误: 无效选项"
                MSG_ARM64_NOT_SUPPORT_V6="ARM64架构暂不支持安装v6版本"
                MSG_SELECTED_VERSION="已选择版本:"
                MSG_FILE_DOWNLOAD="下载文件: "
                MSG_DOWNLOAD_ERROR="错误: wget 或 curl 都未安装，无法下载文件。"
                MSG_EXTRACT_ERROR="错误: unzip 或 gunzip 都未安装，无法解压文件。"
                MSG_DOWNLOAD_FAILED="错误: 下载失败！"
                MSG_OPERATION_ABORTED="错误: 操作已中止。"
                MSG_WARNING="警告：/dev/%s 上的数据将会丢失！"
                MSG_REBOOTING="好的，正在重启..."
                MSG_ADMIN_PASSWORD="管理员密码:"
                MSG_MANUAL_PASS_CHOICE="是否手动输入密码？(y/N): "
                MSG_ENTER_NEW_PASS="请输入新密码: "
                MSG_PASS_EMPTY="密码不能为空，请重新输入。"
                MSG_ERROR_MOUNT="错误: 挂载分区失败"
                MSG_ERROR_LOOP="错误: 设置 loop 设备失败"
                MSG_AUTO_RUN_FILE_CREATED="autorun.scr 文件已创建。"
                MSG_AUTO_RUN_FILE_NOT_CREATED="警告：autorun.scr 文件创建失败!"
                MSG_CONFIRM_CONTINUE="您是否确定继续? [y/n]"
                ;;
            *)
                echo "Error: Invalid option!"
                continue
                ;;
        esac
        break
    done
}


show_system_info() {
    ARCH=$(uname -m)
    BOOT_MODE=$( [ -d "/sys/firmware/efi" ] && echo "UEFI" || echo "BIOS" )
    echo "$MSG_ARCH $ARCH"
    echo "$MSG_BOOTMODE $BOOT_MODE"
}

confirm_storge() {
    if command -v lsblk >/dev/null 2>&1; then
        STORAGE=$(lsblk -d -n -o NAME,TYPE | awk '$2=="disk"{print $1; exit}')
    else
        STORAGE=$(fdisk -l | awk '/^Disk \/dev/ {print $2; exit}' | sed 's#:##' | sed 's#/dev/##')
    fi
    ask_until "$MSG_STORAGE_DEVICE" "$STORAGE"
    STORAGE=$resp
}
confirm_address() {
    ETH=$(ip route show default | grep '^default' | sed -n 's/.* dev \([^\ ]*\) .*/\1/p')
    ADDRESS=$(ip addr show $ETH | grep global | cut -d' ' -f 6 | head -n 1)
    GATEWAY=$(ip route list | grep default | cut -d' ' -f 3)
    if [ -f "/etc/resolv.conf" ]; then
        DNS=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | head -n 1)
    fi
    [ -z "$DNS" ] && DNS="8.8.8.8"
    ask_until "$MSG_ADDRESS" "$ADDRESS"
    ADDRESS=$resp
    ask_until "$MSG_GATEWAY" "$GATEWAY"
    GATEWAY=$resp
    ask_until "$MSG_DNS" "$DNS"
    DNS=$resp
}

http_get() {
    local url=$1
    local dest_file=$2
    if command -v curl >/dev/null 2>&1; then
        if [ -z "$dest_file" ]; then
            curl -Ls "$url"
        else
            curl -L -# -o "$dest_file" "$url" || { echo "$MSG_DOWNLOAD_FAILED"; exit 1; }
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -z "$dest_file" ]; then
            wget --no-check-certificate -qO- "$url"
        else
            wget --no-check-certificate -O "$dest_file" "$url" || { echo "$MSG_DOWNLOAD_FAILED"; exit 1; }
        fi
    else
        echo "$MSG_DOWNLOAD_ERROR"
        exit 1
    fi
}

extract_zip() {
    local zip_file=$1
    local dest_file=$2
    if command -v unzip >/dev/null 2>&1; then
        unzip -p "$zip_file" > "$dest_file" || { echo "$MSG_EXTRACT_ERROR"; exit 1; }
    elif command -v gunzip >/dev/null 2>&1; then
        gunzip -c "$zip_file" > "$dest_file" || { echo "$MSG_EXTRACT_ERROR"; exit 1; }
    else
        echo "$MSG_EXTRACT_ERROR"
        exit 1
    fi
}


select_version() {
    if [[ -n "$VERSION" ]]; then
        if [[ "$VERSION" == 7.* ]]; then
            V7=1
        elif [[ "$VERSION" == 6.* ]]; then
            V7=0
        else
            echo "Error: Unsupported version $VERSION"
            exit 1
        fi
        echo "$MSG_SELECTED_VERSION $VERSION"
        return
    fi
    while true; do
        case $ARCH in
            x86_64|i386|i486|i586|i686)
                echo "$MSG_SELECT_VERSION"
                echo "1. $MSG_STABLE"
                echo "2. $MSG_TEST"
                echo "3. $MSG_LTS"
                echo "4. $MSG_STABLE6"
                read -p "$MSG_PLEASE_CHOOSE [1-4]" version_choice
                ;; 
            aarch64)
                echo "$MSG_SELECT_VERSION"
                echo "1. $MSG_STABLE"
                echo "2. $MSG_TEST"
                read -p "$MSG_PLEASE_CHOOSE [1-2]" version_choice
                ;; 
            *)
                echo "$MSG_UNSUPPORTED_ARCH $ARCH"
                exit 1
                ;;
        esac
        case $version_choice in
            1) 
                VERSION=$(http_get "https://upgrade.mikrotik.ltd/routeros/NEWESTa7.stable" | cut -d' ' -f1)
                V7=1
                ;;
            2) 
                VERSION=$(http_get "https://upgrade.mikrotik.ltd/routeros/NEWESTa7.testing" | cut -d' ' -f1)
                V7=1
                ;;
            3)
                if [[ "$ARCH" == "aarch64" ]]; then
                    echo "$MSG_ARM64_NOT_SUPPORT_V6"
                    continue
                fi
                VERSION=$(http_get "https://upgrade.mikrotik.ltd/routeros/NEWEST6.long-term" | cut -d' ' -f1)
                V7=0
                ;;
            4)
                if [[ "$ARCH" == "aarch64" ]]; then
                    echo "$MSG_ARM64_NOT_SUPPORT_V6"
                    continue
                fi
                VERSION=$(http_get "https://upgrade.mikrotik.ltd/routeros/NEWEST6.stable" | cut -d' ' -f1)
                V7=0
                ;;
            *)
                echo "$MSG_INVALID_OPTION"
                continue
                ;;
        esac
        echo "$MSG_SELECTED_VERSION $VERSION"
        break
    done
}

download_image(){
    case $ARCH in
        x86_64|i386|i486|i586|i686)
            if [[ $V7 == 1 && $BOOT_MODE == "BIOS" ]]; then
                IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$VERSION/chr-$VERSION-legacy-bios.img.zip"
            else
                IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$VERSION/chr-$VERSION.img.zip"
            fi
            ;; 
        aarch64)
             IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$VERSION-arm64/chr-$VERSION-arm64.img.zip"
            ;; 
        *)
            echo "$MSG_UNSUPPORTED_ARCH"
            exit 1
            ;;
    esac
    echo "$MSG_FILE_DOWNLOAD $(basename "$IMG_URL")"
    http_get "$IMG_URL" "/tmp/chr.img.zip"
    cd /tmp
    extract_zip "chr.img.zip" chr.img
}

create_autorun() {
    if LOOP=$(losetup -Pf --show chr.img 2>/dev/null); then
        sleep 1
        MNT=/tmp/chr
        mkdir -p $MNT
        PARTITION=$([ "$V7" == 1 ] && echo "p2" || echo "p1")
        if mount "${LOOP}${PARTITION}" "$MNT" 2>/dev/null; then
            confirm_address
            RANDOM_ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
            ask_until "$MSG_ADMIN_PASSWORD" "$RANDOM_ADMIN_PASS"
            RANDOM_ADMIN_PASS=$resp
            cat <<EOF > "$MNT/rw/autorun.scr"
/user set admin password="$RANDOM_ADMIN_PASS"
/ip dns set servers=$DNS
/ip address add address=$ADDRESS interface=ether1
/ip route add gateway=$GATEWAY
EOF
            echo "$MSG_AUTO_RUN_FILE_CREATED"
            umount $MNT
            losetup -d "$LOOP"
        else
            losetup -d "$LOOP"
            echo "$MSG_ERROR_MOUNT $PARTITION"
            echo "$MSG_AUTO_RUN_FILE_NOT_CREATED"
        fi
    else
        echo "$MSG_ERROR_LOOP"
        echo "$MSG_AUTO_RUN_FILE_NOT_CREATED"
    fi
}


write_and_reboot() {
	confirm_storge
    printf "$MSG_WARNING\n" "$STORAGE"
    ask_yesno "$MSG_CONFIRM_CONTINUE"
    if [ $? -ne 0 ]; then
        echo "$MSG_OPERATION_ABORTED"
        exit 1
    fi
    dd if=chr.img of=/dev/$STORAGE bs=4M conv=fsync
    echo "$MSG_REBOOTING"
    echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
    echo b > /proc/sysrq-trigger 2>/dev/null || true
    reboot -f
}

select_language
show_system_info
select_version
download_image
create_autorun
write_and_reboot
exit 0
