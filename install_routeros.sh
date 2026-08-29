#!/bin/zsh
BACKTITLE="MikroTik RouterOS LiveCD Installer"
TITLE="Installation Wizard"

WORK_DIR="${WORK_DIR:-/tmp/ros_install}"
BUILD_DIR="$WORK_DIR/build"
BACKUP_DIR="$WORK_DIR/rw_backup"
BOOT_MNT="$WORK_DIR/mnt_boot"
ROS_MNT="$WORK_DIR/mnt_ros"
PROBE_MNT="$WORK_DIR/mnt_probe"
LOG_FILE="$WORK_DIR/install.log"

NPK_DIR=""
MAIN_NPK=""
OPT_NPK=""
typeset -a COMP_NPK_LIST
typeset -a SELECTED_PACKAGES
TARGET_DISK=""
KEEP_CONFIG="no"
EXISTING_ROS_PART=""
LAST_ERROR=""

# ------------------------------------------------------------------------------
# Helper functions: Logging & Cleanup
# ------------------------------------------------------------------------------
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" >> "$LOG_FILE"
}

cleanup_mounts() {
    sync
    umount "$BOOT_MNT" 2>/dev/null || true
    umount "$ROS_MNT" 2>/dev/null || true
    if [[ -d "$PROBE_MNT" ]]; then
        for m in "$PROBE_MNT"/*(N/); do
            umount "$m" 2>/dev/null || true
        done
    fi
}

# ------------------------------------------------------------------------------
# Filter: Detect CD-ROM and USB devices
# ------------------------------------------------------------------------------
is_cdrom() {
    local dev="$1"
    [[ -b "$dev" ]] || return 1
    local name="${dev:t}"

    # 1. Standard optical drive names (/dev/sr*, /dev/cdrom*)
    [[ "$name" =~ ^(sr|cdrom) ]] && return 0

    # 2. Optical filesystem signatures (ISO9660, UDF)
    local blkinfo
    blkinfo=$(blkid "$dev" 2>/dev/null)
    if [[ "$blkinfo" =~ (TYPE=\"iso9660\"|TYPE=\"udf\"|iso9660|udf) ]]; then
        return 0
    fi

    # 3. SCSI device type 5 (CD-ROM/DVD)
    local diskname="$name"
    if [[ -f "/sys/class/block/$name/partition" ]]; then
        diskname=$(lsblk -no PKNAME "$dev" 2>/dev/null | head -n 1)
        [[ -z "$diskname" ]] && diskname="${name%%[0-9]*}"
    fi
    if [[ -f "/sys/block/$diskname/device/type" ]]; then
        local dev_type
        dev_type=$(cat "/sys/block/$diskname/device/type" 2>/dev/null)
        [[ "$dev_type" == "5" ]] && return 0
    fi

    return 1
}

is_usb() {
    local dev="$1"
    [[ -b "$dev" ]] || return 1
    local name="${dev:t}"

    local diskname="$name"
    if [[ -f "/sys/class/block/$name/partition" ]]; then
        diskname=$(lsblk -no PKNAME "$dev" 2>/dev/null | head -n 1)
        [[ -z "$diskname" ]] && diskname="${name%%[0-9]*}"
    fi

    # 1. sysfs device tree path containing /usb
    local syspath
    syspath=$(readlink -f "/sys/class/block/$diskname" 2>/dev/null || readlink -f "/sys/block/$diskname" 2>/dev/null)
    if [[ "$syspath" == *"/usb"* ]]; then
        return 0
    fi

    # 2. lsblk transport attribute
    local tran
    tran=$(lsblk -no TRAN "$dev" 2>/dev/null | head -n 1)
    [[ "$tran" == "usb" ]] && return 0

    # 3. udev property
    if type udevadm >/dev/null 2>&1; then
        local bus
        bus=$(udevadm info -q property -n "$dev" 2>/dev/null | grep -E '^ID_BUS=' | cut -d= -f2)
        [[ "$bus" == "usb" ]] && return 0
    fi

    return 1
}

is_cdrom_or_usb() {
    is_cdrom "$1" || is_usb "$1"
}

# ------------------------------------------------------------------------------
# Check if a device or its symlink is already mounted
# ------------------------------------------------------------------------------
is_device_mounted() {
    local dev="$1"
    [[ -b "$dev" ]] || return 1
    local realdev
    realdev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")
    
    if awk '{print $1}' /proc/mounts 2>/dev/null | grep -q -x -E "($realdev|$dev)"; then
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# Discover and Mount Installation Media
# ------------------------------------------------------------------------------
discover_and_mount_media() {
    mkdir -p /media/cdrom /media/usb "$PROBE_MNT"
    
    # 1. Check optical drives (/dev/sr0, /dev/cdrom, etc.)
    for dev in /dev/sr[0-9]* /dev/cdrom*(N); do
        [[ -b "$dev" ]] || continue
        
        is_device_mounted "$dev" && continue
        
        local realdev
        realdev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")
        is_device_mounted "$realdev" && continue

        local target_mnt="$PROBE_MNT/${realdev:t}"
        if ! grep -q " /media/cdrom " /proc/mounts 2>/dev/null; then
            target_mnt="/media/cdrom"
        fi
        mkdir -p "$target_mnt"

        mount -t iso9660 -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t udf -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || true
    done

    # 2. Scan block devices from /sys/class/block/ (USB flash drives, etc.)
    for b in /sys/class/block/*(N); do
        local dev="/dev/${b:t}"
        [[ -b "$dev" ]] || continue
        
        is_cdrom_or_usb "$dev" || continue

        is_device_mounted "$dev" && continue

        local realdev
        realdev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")
        is_device_mounted "$realdev" && continue

        local target_mnt="$PROBE_MNT/${realdev:t}"
        if ! grep -q " /media/usb " /proc/mounts 2>/dev/null; then
            target_mnt="/media/usb"
        fi
        mkdir -p "$target_mnt"

        mount -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t iso9660 -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t udf -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t vfat -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t ext4 -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t ntfs -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || true
    done
}

get_media_dirs() {
    local -a dirs

    # Inspect all currently mounted directories from /proc/mounts
    while read -r dev mnt rest; do
        [[ -d "$mnt" ]] || continue
        [[ "$mnt" == "/" || "$mnt" == "/proc"* || "$mnt" == "/sys"* || "$mnt" == "/dev"* ]] && continue
        
        if is_cdrom_or_usb "$dev" || [[ "$mnt" =~ ^(/media|/cdrom|/mnt|/run/media|"$PROBE_MNT") ]]; then
            dirs+=("$mnt")
        fi
    done < /proc/mounts

    # Deduplicate mount points
    local -a unique_dirs
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        if ! (( ${unique_dirs[(Ie)$d]} )); then
            unique_dirs+=("$d")
        fi
    done

    echo "${unique_dirs[@]}"
}

# ------------------------------------------------------------------------------
# Step 1: Scan & Mount Media for NPK packages
# ------------------------------------------------------------------------------
scan_media_npk() {
    local fifo="$WORK_DIR/gauge_scan_fifo"
    rm -f "$fifo"
    mkfifo "$fifo"

    dialog --backtitle "$BACKTITLE" --title "$TITLE" --gauge "Detecting and mounting installation media..." 8 70 0 < "$fifo" &
    local gauge_pid=$!
    exec 3> "$fifo"

    gauge_update() {
        local pct="$1"
        local msg="$2"
        printf "XXX\n%d\n%s\nXXX\n" "$pct" "$msg" >&3 2>/dev/null || true
    }

    gauge_update 10 "Checking and mounting CD-ROM and USB media..."
    discover_and_mount_media
    sleep 0.3

    local media_dirs=($(get_media_dirs))
    log "Found media directories to scan: ${media_dirs[*]}"

    if [[ ${#media_dirs[@]} -eq 0 ]]; then
        gauge_update 100 "No CD-ROM or USB media detected."
        sleep 0.5
        exec 3>&-
        kill $gauge_pid 2>/dev/null || true
        wait $gauge_pid 2>/dev/null || true
        rm -f "$fifo"
        return 1
    fi

    gauge_update 30 "Searching for RouterOS packages (*.npk) on media..."
    sleep 0.2

    MAIN_NPK=""
    OPT_NPK=""
    COMP_NPK_LIST=()
    local -a found_files

    local idx=0
    for m in "${media_dirs[@]}"; do
        idx=$(( idx + 1 ))
        local cur_pct=$(( 30 + idx * 10 ))
        [[ $cur_pct -gt 70 ]] && cur_pct=70
        gauge_update "$cur_pct" "Scanning media: $m"
        
        for f in "$m"/*.npk(N) "$m"/*/*.npk(N) "$m"/packages/*.npk(N); do
            [[ -f "$f" ]] || continue
            if ! (( ${found_files[(Ie)$f]} )); then
                found_files+=("$f")
                log "Found NPK: $f"
            fi
        done
    done

    gauge_update 80 "Classifying NPK packages..."
    sleep 0.2

    # Deduplicate component packages by package name tag
    typeset -A seen_tags
    for f in "${found_files[@]}"; do
        local bn=$(basename "$f")
        case "$bn" in
            routeros-*.npk)
                [[ -z "$MAIN_NPK" ]] && MAIN_NPK="$f"
                ;;
            option-*.npk)
                [[ -z "$OPT_NPK" ]] && OPT_NPK="$f"
                ;;
            *)
                local tag="${bn%.npk}"
                tag="${tag%-[0-9]*}"
                if [[ -z "${seen_tags[$tag]}" ]]; then
                    seen_tags[$tag]=1
                    COMP_NPK_LIST+=("$f")
                fi
                ;;
        esac
    done

    if [[ -n "$MAIN_NPK" ]]; then
        NPK_DIR="${MAIN_NPK:h}"
        gauge_update 100 "Found main package: $(basename "$MAIN_NPK")"
        log "Scanned MAIN_NPK: $MAIN_NPK"
        [[ -n "$OPT_NPK" ]] && log "Scanned OPT_NPK: $OPT_NPK"
        log "Scanned components count: ${#COMP_NPK_LIST[@]}"
    else
        gauge_update 100 "No routeros-*.npk main package found on CD/USB."
        log "No routeros-*.npk found on scanned media"
    fi

    sleep 0.4
    exec 3>&-
    kill $gauge_pid 2>/dev/null || true
    wait $gauge_pid 2>/dev/null || true
    rm -f "$fifo"

    [[ -n "$MAIN_NPK" ]] && return 0
    return 1
}

step_scan() {
    while :; do
        if scan_media_npk; then
            return 0
        fi

        # Main NPK not found prompt
        dialog --backtitle "$BACKTITLE" --title "$TITLE" \
            --yes-label "Retry" \
            --no-label "Exit" \
            --yesno "No RouterOS main package (routeros-*.npk) was found on CD-ROM or USB media.\n\nPlease connect the CD-ROM or USB installation drive.\n\n- Select [Retry] to rescan CD-ROM and USB media\n- Select [Exit] to cancel and return to shell" 13 70
        local rc=$?
        if [[ $rc -eq 0 ]]; then
            continue
        else
            return 255
        fi
    done
}

# ------------------------------------------------------------------------------
# Step 2: Component Package Selection
# ------------------------------------------------------------------------------
step_packages() {
    if [[ ${#COMP_NPK_LIST[@]} -eq 0 ]]; then
        dialog --backtitle "$BACKTITLE" --title "$TITLE" \
            --ok-label "Next" \
            --cancel-label "Back" \
            --extra-button --extra-label "Exit" \
            --msgbox "No optional component packages found on media. Only the main system package will be installed.\n\nMain package: $(basename "$MAIN_NPK")" 11 70
        local rc=$?
        case $rc in
            0) return 0 ;;      # Next
            1) return 1 ;;      # Back
            3|255) return 255 ;; # Exit
        esac
    fi

    local -a check_items
    typeset -A added_tags
    for f in "${COMP_NPK_LIST[@]}"; do
        local bn=$(basename "$f")
        local tag="${bn%.npk}"
        tag="${tag%-[0-9]*}"
        
        # Strictly ensure unique tags
        [[ -n "${added_tags[$tag]}" ]] && continue
        added_tags[$tag]=1
        
        local is_on="ON"
        if [[ ${#SELECTED_PACKAGES[@]} -gt 0 ]]; then
            if (( ${SELECTED_PACKAGES[(Ie)$tag]} )); then
                is_on="ON"
            else
                is_on="OFF"
            fi
        fi
        check_items+=("$tag" "$bn" "$is_on")
    done

    local choice
    choice=$(dialog --stdout --backtitle "$BACKTITLE" --title "$TITLE" \
        --separate-output \
        --ok-label "Next" \
        --cancel-label "Back" \
        --extra-button --extra-label "Exit" \
        --checklist "Select optional component packages to install (SPACE to toggle, TAB to switch buttons):" 18 72 8 \
        "${check_items[@]}")
    local rc=$?

    log "step_packages returned code: $rc, choice: ${choice:-<empty>}"

    case $rc in
        0)
            if [[ -n "$choice" ]]; then
                SELECTED_PACKAGES=(${(f)choice})
            else
                SELECTED_PACKAGES=()
            fi
            log "Selected packages: ${SELECTED_PACKAGES[*]}"
            return 0
            ;;
        1)
            # Back to step 0
            return 1
            ;;
        3|255)
            # Exit wizard
            return 255
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Step 3: Target Disk Selection
# ------------------------------------------------------------------------------
step_disk() {
    local -a menu_items

    # Scan all disk block devices: SATA, SAS, NVMe, VirtIO (vda), Xen (xvda), IDE (hda), eMMC (mmcblk)
    while read -r dev size type model; do
        [[ "$type" == "disk" ]] || continue
        
        local devname="${dev:t}"
        # Exclude RAM, Loop, ZRAM, and optical CD-ROM devices
        [[ "$devname" =~ ^(loop|ram|zram|sr) ]] && continue
        
        # Exclude USB flash drives and USB installation media
        if is_cdrom_or_usb "$dev"; then
            continue
        fi

        # Construct friendly description
        local desc="${size}"
        if [[ -n "$model" ]]; then
            desc+=" ${model}"
        else
            if [[ "$devname" =~ ^vd ]]; then
                desc+=" VirtIO-Disk"
            elif [[ "$devname" =~ ^xvd ]]; then
                desc+=" Xen-VDisk"
            elif [[ "$devname" =~ ^nvme ]]; then
                desc+=" NVMe-SSD"
            elif [[ "$devname" =~ ^hd ]]; then
                desc+=" IDE/ATA-Disk"
            elif [[ "$devname" =~ ^sd ]]; then
                desc+=" SATA/SCSI-Disk"
            elif [[ "$devname" =~ ^mmcblk ]]; then
                desc+=" eMMC-Storage"
            else
                desc+=" Hard-Disk"
            fi
        fi

        menu_items+=("$dev" "$desc")
    done < <(lsblk -d -p -n -o NAME,SIZE,TYPE,MODEL 2>/dev/null)

    if [[ ${#menu_items[@]} -eq 0 ]]; then
        dialog --backtitle "$BACKTITLE" --title "$TITLE" \
            --msgbox "No usable target hard disk found!\n\n(USB drives and CD-ROMs are excluded from target disks)" 11 62
        return 1
    fi

    local choice
    choice=$(dialog --stdout --backtitle "$BACKTITLE" --title "$TITLE" \
        --ok-label "Next" \
        --cancel-label "Back" \
        --extra-button --extra-label "Exit" \
        --menu "Select target disk for RouterOS installation (Physical & Virtual Disks):\n\n[WARNING] ALL EXISTING DATA ON THIS DISK WILL BE ERASED!" 18 74 7 \
        "${menu_items[@]}")
    local rc=$?

    case $rc in
        0)
            TARGET_DISK="$choice"
            log "Target disk selected: $TARGET_DISK"
            return 0
            ;;
        1)
            return 1
            ;;
        3|255)
            return 255
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Step 4: Existing Installation & Config Retention
# ------------------------------------------------------------------------------
step_existing() {
    EXISTING_ROS_PART=""
    EXISTING_ROS_PART=$(blkid -L "RouterOS" 2>/dev/null | head -n 1)

    if [[ -z "$EXISTING_ROS_PART" ]]; then
        mkdir -p "$ROS_MNT"
        for dev in $(lsblk -p -o NAME -n 2>/dev/null | grep -E '^/dev/'); do
            if mount -o ro "$dev" "$ROS_MNT" 2>/dev/null; then
                if [[ -f "$ROS_MNT/rw/store" || -d "$ROS_MNT/rw/disk" ]]; then
                    EXISTING_ROS_PART="$dev"
                    umount "$ROS_MNT" 2>/dev/null || true
                    break
                fi
                umount "$ROS_MNT" 2>/dev/null || true
            fi
        done
    fi

    if [[ -n "$EXISTING_ROS_PART" ]]; then
        dialog --backtitle "$BACKTITLE" --title "$TITLE" \
            --yes-label "Keep Config" \
            --no-label "Clean Install" \
            --extra-button --extra-label "Back" \
            --yesno "An existing RouterOS installation was detected ($EXISTING_ROS_PART).\n\nDo you want to backup and preserve existing configuration (/rw)?\n\n- [Keep Config]: Backup and restore /rw after installation\n- [Clean Install]: Completely wipe configuration" 15 70
        local rc=$?
        case $rc in
            0)
                KEEP_CONFIG="yes"
                log "Keep config: yes (from $EXISTING_ROS_PART)"
                return 0
                ;;
            1)
                KEEP_CONFIG="no"
                log "Keep config: no"
                return 0
                ;;
            3)
                # Back to step 2
                return 1
                ;;
            255)
                return 255
                ;;
        esac
    fi

    KEEP_CONFIG="no"
    return 0
}

# ------------------------------------------------------------------------------
# Step 5: Installation Summary & Execution
# ------------------------------------------------------------------------------
step_install() {
    local pkgs_str="None (Main system only)"
    if [[ ${#SELECTED_PACKAGES[@]} -gt 0 ]]; then
        pkgs_str="${(j:, :)SELECTED_PACKAGES}"
    fi

    local summary="Please review the installation details:\n\n"
    summary+="  • Media Directory : $NPK_DIR\n"
    summary+="  • Main Package    : $(basename "$MAIN_NPK")\n"
    summary+="  • Components      : $pkgs_str\n"
    summary+="  • Target Disk     : $TARGET_DISK\n"
    summary+="  • Keep Config     : $KEEP_CONFIG\n\n"
    summary+="[WARNING] Clicking [Install] will partition and format $TARGET_DISK.\nALL EXISTING DATA WILL BE PERMANENTLY ERASED!"

    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
        --ok-label "Install" \
        --cancel-label "Back" \
        --extra-button --extra-label "Exit" \
        --yesno "$summary" 17 72
    local rc=$?

    case $rc in
        0) ;; # Proceed with installation
        1) return 1 ;; # Back to step 3
        3|255) return 255 ;; # Exit
    esac

    # Start Installation
    : > "$LOG_FILE"
    LAST_ERROR=""

    local fifo="$WORK_DIR/gauge_install_fifo"
    rm -f "$fifo"
    mkfifo "$fifo"

    # Expanded height (16 rows) to display rolling progress steps and results
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --gauge "Preparing installation environment..." 16 76 0 < "$fifo" &
    local gauge_pid=$!
    exec 3> "$fifo"

    typeset -a INSTALL_LOG_STEPS

    gauge_install_log() {
        local pct="$1"
        local step_state="$2" # "run", "done", "fail"
        local msg="$3"

        if [[ "$step_state" == "run" ]]; then
            INSTALL_LOG_STEPS+=(" [->] $msg")
        elif [[ "$step_state" == "done" ]]; then
            if [[ ${#INSTALL_LOG_STEPS[@]} -gt 0 && "${INSTALL_LOG_STEPS[-1]}" =~ "^\ \[->\]" ]]; then
                INSTALL_LOG_STEPS[-1]=" [OK] $msg"
            else
                INSTALL_LOG_STEPS+=(" [OK] $msg")
            fi
        elif [[ "$step_state" == "fail" ]]; then
            INSTALL_LOG_STEPS+=(" [ERR] $msg")
        fi

        # Keep last 7 lines in the display window
        while [[ ${#INSTALL_LOG_STEPS[@]} -gt 7 ]]; do
            shift INSTALL_LOG_STEPS
        done

        local text="${(F)INSTALL_LOG_STEPS}"
        printf "XXX\n%d\n%s\nXXX\n" "$pct" "$text" >&3 2>/dev/null || true
    }

    # Execution Routine
    do_install_process() {
        set -e
        trap 'LAST_ERROR="Command failed at line $LINENO: $BASH_COMMAND"' ERR

        # 1. Environment prep & config backup
        gauge_install_log 5 "run" "Step 1/8: Initializing environment & kernel modules..."
        log "Step 1: Init environment"
        cleanup_mounts
        mkdir -p "$BUILD_DIR" "$BACKUP_DIR" "$BOOT_MNT" "$ROS_MNT"
        rm -rf "$BUILD_DIR/sq"
        sleep 0.3

        if [[ "$KEEP_CONFIG" == "yes" && -n "$EXISTING_ROS_PART" ]]; then
            gauge_install_log 10 "run" "Backing up existing configuration (/rw)..."
            log "Backing up config from $EXISTING_ROS_PART"
            sleep 0.3
            mkdir -p "$ROS_MNT"
            if mount -o ro "$EXISTING_ROS_PART" "$ROS_MNT" 2>/dev/null; then
                rm -rf "$BACKUP_DIR/rw"
                mkdir -p "$BACKUP_DIR/rw"
                cp -a "$ROS_MNT/rw/." "$BACKUP_DIR/rw/" 2>/dev/null || true
                umount "$ROS_MNT" 2>/dev/null || true
                log "Config backup finished"
                gauge_install_log 12 "done" "Step 1/8: Environment ready & config backed up"
            else
                log "Warning: Could not mount $EXISTING_ROS_PART to backup /rw"
                gauge_install_log 12 "done" "Step 1/8: Environment ready (config backup skipped)"
                sleep 0.3
            fi
        else
            gauge_install_log 12 "done" "Step 1/8: Environment & modules initialized"
            sleep 0.3
        fi
        

        # 2. Extract NPK FILE_CONTAINER (bootloader, milo, EFI files)
        gauge_install_log 18 "run" "Step 2/8: Extracting NPK FILE_CONTAINER (boot files)..."
        log "Step 2: Extracting NPK FILE_CONTAINER from $MAIN_NPK"
        sleep 0.3
        local sq="$BUILD_DIR/sq"
        rm -rf "$sq" && mkdir -p "$sq"

        local npkextract_bin
        npkextract_bin=$(command -v npkextract 2>/dev/null || echo "")
        if [[ -z "$npkextract_bin" ]]; then
            gauge_install_log 18 "fail" "Step 2/8: npkextract not found in PATH"
            LAST_ERROR="npkextract is required but not found. Please ensure it is installed in the LiveCD."
            return 1
        fi

        log "Using npkextract: $npkextract_bin"
        if ! "$npkextract_bin" "$MAIN_NPK" "$sq" >> "$LOG_FILE" 2>&1; then
            gauge_install_log 18 "fail" "Step 2/8: npkextract failed on $MAIN_NPK"
            LAST_ERROR="npkextract failed to extract FILE_CONTAINER from $MAIN_NPK"
            return 1
        fi

        # Verify key boot files were extracted
        if [[ ! -f "$sq/bin/milo" && ! -f "$sq/boot/EFI/BOOT/BOOTX64.EFI" ]]; then
            gauge_install_log 18 "fail" "Step 2/8: No boot files found after extraction"
            LAST_ERROR="npkextract ran but neither milo nor BOOTX64.EFI was found in the NPK"
            return 1
        fi

        log "Extracted: milo=$(test -f $sq/bin/milo && echo yes || echo no), EFI=$(test -f $sq/boot/EFI/BOOT/BOOTX64.EFI && echo yes || echo no)"
        gauge_install_log 25 "done" "Step 2/8: Boot files extracted (milo + EFI ready)"
        sleep 0.3

        # Detect boot mode early (needed for partitioning and bootloader steps)
        local is_uefi=0
        if [[ -d /sys/firmware/efi ]]; then
            is_uefi=1
            log "Boot mode: UEFI (EFI runtime variables found at /sys/firmware/efi)"
        else
            log "Boot mode: BIOS/Legacy (no EFI runtime variables found)"
        fi

        # 3. Disk partitioning
        gauge_install_log 32 "run" "Step 3/8: Partitioning $TARGET_DISK ..."
        log "Step 3: Partitioning $TARGET_DISK (is_uefi=$is_uefi)"
        sleep 0.3

        dd if=/dev/zero of="$TARGET_DISK" bs=512 count=1 conv=notrunc
        sync
        # Build common sgdisk arguments
        local sgdisk_args=(
            --zap-all
            --set-alignment=1
            --new=1:34:+32M   --typecode=1:8300 --change-name=1:"RouterOS Boot" --attributes=1:set:2
            --new=2:0:-4096   --typecode=2:8300 --change-name=2:"RouterOS"
        )
        if ! sgdisk "${sgdisk_args[@]}" --gpttombr=1:2 "$TARGET_DISK" >> "$LOG_FILE" 2>&1; then
            gauge_install_log 32 "fail" "Step 3/8: sgdisk (BIOS+gpttombr) failed on $TARGET_DISK"
            LAST_ERROR="sgdisk --gpttombr failed on $TARGET_DISK"
            return 1
        fi
        
        # Save the hybrid MBR (first 512 bytes, which now has MBR partition table)
        local mbr_tmp="$BUILD_DIR/mbr.bin"
        dd if="$TARGET_DISK" of="$mbr_tmp" bs=512 count=1 conv=notrunc >> "$LOG_FILE" 2>&1 || {
            gauge_install_log 32 "fail" "Step 3/8: Failed to read MBR from $TARGET_DISK"
            LAST_ERROR="dd failed to read MBR from $TARGET_DISK"
            return 1
        }
        # Byte 446: set to 0x80 (mark first MBR partition as active/bootable)
        printf '\x80' | dd of="$mbr_tmp" bs=1 count=1 seek=446 conv=notrunc >> "$LOG_FILE" 2>&1 || true
        if [[ $is_uefi -eq 0 ]]; then
            # Write MikroTik BIOS bootstrap code into bytes 0-439 of the saved MBR
            printf '%s' "FA31C08ED0BC007C89E65007501FFBFCBF0006B90001F2A5EA1D060000BEBE07B304803C807423803C00750983C610FECB75EFCD18BE9B06AC3C00740B56BB0700B40ECD105EEBF0EBFE8B148B4C0289F5BF0500BB007CB8010257CD135F730C31C0CD134F75EDBE7C06EBCCBFFE7D813D55AA75C289EEEA007C00004572726F72206C6F6164696E67206F7065726174696E672073797374656D004D697373696E67206F7065726174696E672073797374656D0000000000" \
                | xxd -r -p \
                | dd of="$mbr_tmp" bs=1 count=440 conv=notrunc >> "$LOG_FILE" 2>&1 || {
                    gauge_install_log 32 "fail" "Step 3/8: Failed to write MBR bootstrap code"
                    LAST_ERROR="Failed to write MikroTik BIOS bootstrap into MBR"
                    return 1
                }
        fi
        # Second pass: recreate clean GPT (without --gpttombr, so GPT backup is clean)
        if ! sgdisk "${sgdisk_args[@]}" "$TARGET_DISK" >> "$LOG_FILE" 2>&1; then
            gauge_install_log 32 "fail" "Step 3/8: sgdisk (GPT rebuild) failed on $TARGET_DISK"
            LAST_ERROR="sgdisk GPT rebuild failed on $TARGET_DISK"
            return 1
        fi
        # Restore  MBR (bootstrap + hybrid MBR partition table)
        dd if="$mbr_tmp" of="$TARGET_DISK" bs=512 count=1 conv=notrunc >> "$LOG_FILE" 2>&1 || {
            gauge_install_log 32 "fail" "Step 3/8: Failed to write MBR to $TARGET_DISK"
            LAST_ERROR="dd failed to write MBR back to $TARGET_DISK"
            return 1
        }
        rm -f "$mbr_tmp"
        log "BIOS hybrid MBR written to $TARGET_DISK"

        # Force kernel to reread partition table & trigger mdev/udev
        partprobe "$TARGET_DISK" >> "$LOG_FILE" 2>&1 || true
        blockdev --rereadpt "$TARGET_DISK" 2>/dev/null || true
        partx -u "$TARGET_DISK" 2>/dev/null || partx -a "$TARGET_DISK" 2>/dev/null || true
        mdev -s 2>/dev/null || true
        type udevadm >/dev/null 2>&1 && udevadm settle 2>/dev/null || true

        # Calculate partition paths (nvme0n1p1, mmcblk0p1, vda1, sda1, etc.)
        local bootp rosp
        if [[ "$TARGET_DISK" =~ [0-9]$ ]]; then
            bootp="${TARGET_DISK}p1"
            rosp="${TARGET_DISK}p2"
        else
            bootp="${TARGET_DISK}1"
            rosp="${TARGET_DISK}2"
        fi

        # Wait and ensure partition device nodes exist in /dev
        for p in "$bootp" "$rosp"; do
            local wait_count=0
            while [[ ! -b "$p" && $wait_count -lt 15 ]]; do
                sleep 0.2
                wait_count=$(( wait_count + 1 ))
                mdev -s 2>/dev/null || true

                local pname="${p:t}"
                if [[ -f "/sys/class/block/$pname/dev" ]]; then
                    local maj_min=$(cat "/sys/class/block/$pname/dev")
                    local maj="${maj_min%%:*}"
                    local min="${maj_min#*:}"
                    mknod "$p" b "$maj" "$min" 2>/dev/null || true
                fi
            done
            if [[ ! -b "$p" ]]; then
                gauge_install_log 35 "fail" "Step 3/8: Partition device node $p missing"
                LAST_ERROR="Partition device node $p was not created by kernel"
                return 1
            fi
        done
        gauge_install_log 45 "done" "Step 3/8: Partitioned $TARGET_DISK (Boot 32M + System)"
        sleep 0.3
        

        # 4. Format partitions
        if [[ $is_uefi -eq 1 ]]; then
            gauge_install_log 48 "run" "Step 4/8: Formatting $bootp (FAT) & $rosp (EXT4)..."
            log "Step 4: Formatting $bootp (vfat) and $rosp (ext4)"
            if ! mkfs.vfat -n "Boot" "$bootp" >> "$LOG_FILE" 2>&1 && ! mkfs.vfat -n "Boot" "$bootp" >> "$LOG_FILE" 2>&1; then
                gauge_install_log 48 "fail" "Step 4/8: Failed to format Boot partition ($bootp)"
                LAST_ERROR="mkfs.vfat failed to format Boot partition $bootp"
                return 1
            fi 
        else
            gauge_install_log 48 "run" "Step 4/8: Formatting $bootp (EXT2) & $rosp (EXT4)..."
            log "Step 4: Formatting $bootp (ext2) and $rosp (ext4)"
            if ! mkfs.ext2 -F -m 0 -L "RouterOS Boot" "$bootp" >> "$LOG_FILE" 2>&1 && ! mkfs.ext2 -F -m 0 -L "RouterOS Boot" "$bootp" >> "$LOG_FILE" 2>&1; then
                gauge_install_log 48 "fail" "Step 4/8: Failed to format Boot partition ($bootp)"
                LAST_ERROR="mkfs.ext2 failed to format Boot partition $bootp"
                return 1
            fi 
        fi
        sleep 0.3
        if ! mkfs.ext4 -F -m 0 -L "RouterOS" -m 0 "$rosp" >> "$LOG_FILE" 2>&1; then
            gauge_install_log 48 "fail" "Step 4/8: Failed to format RouterOS partition ($rosp)"
            LAST_ERROR="mkfs.ext4 failed to format RouterOS partition $rosp"
            return 1
        fi
        
        gauge_install_log 58 "done" "Step 4/8: Formatted $bootp & $rosp"
        sleep 0.3

        # 5. Mount and prepare system dirs
        gauge_install_log 62 "run" "Step 5/8: Mounting partitions & creating system layout..."
        log "Step 5: Mounting and creating dirs"
        sleep 0.3
        mkdir -p "$BOOT_MNT" "$ROS_MNT"

        if [[ $is_uefi -eq 0 ]]; then
            if ! mount -t vfat "$bootp" "$BOOT_MNT" >> "$LOG_FILE" 2>&1 && ! mount "$bootp" "$BOOT_MNT" >> "$LOG_FILE" 2>&1; then
                gauge_install_log 62 "fail" "Step 5/8: Failed to mount Boot partition ($bootp)"
                LAST_ERROR="Failed to mount Boot partition $bootp to $BOOT_MNT"
                return 1
            fi
        else
            if ! mount -t ext2 "$bootp" "$BOOT_MNT" >> "$LOG_FILE" 2>&1 && ! mount "$bootp" "$BOOT_MNT" >> "$LOG_FILE" 2>&1; then
                gauge_install_log 62 "fail" "Step 5/8: Failed to mount Boot partition ($bootp)"
                LAST_ERROR="Failed to mount Boot partition $bootp to $BOOT_MNT"
                return 1
            fi
        fi

        if ! mount -t ext4 "$rosp" "$ROS_MNT" >> "$LOG_FILE" 2>&1 && ! mount "$rosp" "$ROS_MNT" >> "$LOG_FILE" 2>&1; then
            gauge_install_log 62 "fail" "Step 5/8: Failed to mount RouterOS partition ($rosp)"
            LAST_ERROR="Failed to mount RouterOS partition $rosp to $ROS_MNT"
            return 1
        fi

        mkdir -p "$ROS_MNT/var/pdb/system" "$ROS_MNT/var/pdb/option" "$ROS_MNT/bin"
        gauge_install_log 70 "done" "Step 5/8: Partitions mounted & directories created"
        sleep 0.3

        # 6. Install bootloader (EFI & Milo, using is_uefi detected in step 3)
        gauge_install_log 73 "run" "Step 6/8: Installing bootloader..."
        log "Step 6: Installing bootloader (is_uefi=$is_uefi)"
        sleep 0.3
        # Install milo to $ROS_MNT/bin/milo (used by both BIOS and UEFI)
        if [[ -f "$sq/bin/milo" ]]; then
            cp "$sq/bin/milo" "$ROS_MNT/bin/milo" 2>> "$LOG_FILE" || {
                gauge_install_log 73 "fail" "Step 6/8: Failed to copy milo to $ROS_MNT/bin/"
                LAST_ERROR="Failed to copy milo to $ROS_MNT/bin/milo"
                return 1
            }
            chmod 755 "$ROS_MNT/bin/milo"
            log "Installed milo -> $ROS_MNT/bin/milo"
        else
            log "Warning: milo not found in extracted NPK at $sq/bin/milo"
        fi

        # Copy the entire boot/ tree (EFI dir, boot map) to BOOT_MNT
        if [[ -d "$sq/boot" ]]; then
            cp -a "$sq/boot/." "$BOOT_MNT/" 2>> "$LOG_FILE" || {
                gauge_install_log 73 "fail" "Step 6/8: Failed to copy boot/ to $BOOT_MNT"
                LAST_ERROR="Failed to copy boot directory to $BOOT_MNT"
                return 1
            }
            log "Copied boot/ tree to $BOOT_MNT"
        else
            log "Warning: boot/ directory not found in extracted NPK at $sq/boot"
        fi

        if [[ $is_uefi -eq 1 ]]; then
            # UEFI boot: EFI files already in place (BOOTX64.EFI was in boot/EFI/BOOT/)
            log "UEFI mode: EFI bootloader in place at $BOOT_MNT/EFI/BOOT/BOOTX64.EFI - milo setup via EFI not needed"
            gauge_install_log 80 "done" "Step 6/8: UEFI boot - EFI bootloader installed"
        else
            # BIOS/Legacy boot: run milo to setup legacy boot sector on BOOT_MNT
            if [[ -f "$ROS_MNT/bin/milo" ]]; then
                log "BIOS mode: running milo $BOOT_MNT to install legacy boot sector"
                "$ROS_MNT/bin/milo" "$BOOT_MNT" >> "$LOG_FILE" 2>&1 || {
                    log "Warning: milo returned non-zero (may be non-fatal on some hardware)"
                }
                gauge_install_log 80 "done" "Step 6/8: BIOS boot - Milo legacy boot sector installed"
            else
                log "Warning: milo not available for BIOS boot setup"
                gauge_install_log 80 "done" "Step 6/8: Bootloader step complete (milo skipped)"
            fi
        fi
        sleep 0.3

        # 7. Copy system images and components
        gauge_install_log 83 "run" "Step 7/8: Writing $(basename "$MAIN_NPK") and packages..."
        log "Step 7: Writing packages"
        sleep 0.3
        if ! cp "$MAIN_NPK" "$ROS_MNT/var/pdb/system/image" 2>> "$LOG_FILE" || [[ ! -s "$ROS_MNT/var/pdb/system/image" ]]; then
            gauge_install_log 83 "fail" "Step 7/8: Failed to write system image"
            LAST_ERROR="Failed to copy main package to $ROS_MNT/var/pdb/system/image"
            return 1
        fi

        if [[ -n "$OPT_NPK" && -f "$OPT_NPK" ]]; then
            cp "$OPT_NPK" "$ROS_MNT/var/pdb/option/image" 2>> "$LOG_FILE" || true
        fi

        for p in "${SELECTED_PACKAGES[@]}"; do
            [[ -z "$p" ]] && continue
            local src=""
            for f in "${COMP_NPK_LIST[@]}"; do
                local bn=$(basename "$f")
                if [[ "$bn" == ${p}-* || "$bn" == ${p}.npk ]]; then
                    src="$f"
                    break
                fi
            done
            if [[ -n "$src" && -f "$src" ]]; then
                log "Installing component $p from $src"
                mkdir -p "$ROS_MNT/var/pdb/$p"
                cp "$src" "$ROS_MNT/var/pdb/$p/image" 2>> "$LOG_FILE" || log "Warning: Failed to copy $p"
            else
                log "Warning: component $p source not found"
            fi
        done
        gauge_install_log 90 "done" "Step 7/8: System image & selected components written"
        sleep 0.3

        # 8. Restore config & sync
        gauge_install_log 93 "run" "Step 8/8: Finalizing configuration & syncing disks..."
        log "Step 8: Finalizing & sync"
        sleep 0.3
        mkdir -p "$ROS_MNT/rw/disk"
        printf '#!/bin/sh\n# before RouterOS loader start\n' > "$ROS_MNT/rw/disk/rc.local"
        chmod +x "$ROS_MNT/rw/disk/rc.local" 2>/dev/null || true

        if [[ "$KEEP_CONFIG" == "yes" && -d "$BACKUP_DIR/rw" ]]; then
            log "Restoring backup /rw configuration"
            rm -rf "$ROS_MNT/rw"
            mv "$BACKUP_DIR/rw" "$ROS_MNT/rw"
            mkdir -p "$ROS_MNT/rw/disk"
            [[ ! -f "$ROS_MNT/rw/disk/rc.local" ]] && printf '#!/bin/sh\n# before RouterOS loader start\n' > "$ROS_MNT/rw/disk/rc.local"
        fi

        sync
        cleanup_mounts
        sleep 0.4
        gauge_install_log 100 "done" "Step 8/8: Installation completed successfully!"
        log "Installation succeeded!"
        sleep 0.8
        return 0
    }

    local install_err=""
    if do_install_process >> "$LOG_FILE" 2>&1; then
        exec 3>&-
        kill $gauge_pid 2>/dev/null || true
        wait $gauge_pid 2>/dev/null || true
        rm -f "$fifo"
        return 0
    else
        install_err="${LAST_ERROR:-An unexpected error occurred during installation. Please check install log.}"
        exec 3>&-
        kill $gauge_pid 2>/dev/null || true
        wait $gauge_pid 2>/dev/null || true
        rm -f "$fifo"
        cleanup_mounts
        LAST_ERROR="$install_err"
        return 2
    fi
}


main() {
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
        --yes-label "Yes" \
        --no-label "No" \
        --yesno "Welcome to MikroTik RouterOS Installation Wizard.\n\nDo you want to start the installation now?\n\n- Select [Yes] to enter installation wizard\n- Select [No] to exit and return to shell" 12 62
    local start_rc=$?

    if [[ $start_rc -ne 0 ]]; then
        echo "Cancelled by user. Exiting wizard, returning to shell."
        exit 0
    fi

    mkdir -p "$BUILD_DIR" "$BACKUP_DIR" "$BOOT_MNT" "$ROS_MNT" "$PROBE_MNT"
    local step=0
    local install_result=0

    while :; do
        case $step in
            0)
                step_scan
                local rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=1
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            1)
                step_packages
                local rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=2
                elif [[ $rc -eq 1 ]]; then
                    step=0
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            2)
                step_disk
                local rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=3
                elif [[ $rc -eq 1 ]]; then
                    step=1
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            3)
                step_existing
                local rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=4
                elif [[ $rc -eq 1 ]]; then
                    step=2
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            4)
                step_install
                local rc=$?
                if [[ $rc -eq 0 ]]; then
                    install_result=0
                    break
                elif [[ $rc -eq 1 ]]; then
                    step=3
                elif [[ $rc -eq 255 ]]; then
                    echo "Installation wizard cancelled."
                    exit 0
                else
                    # Error
                    install_result=1
                    break
                fi
                ;;
        esac
    done

    # --------------------------------------------------------------------------
    # Finish & Reboot / Shell Prompt
    # --------------------------------------------------------------------------
    if [[ $install_result -eq 0 ]]; then
        # Installation Success
        dialog --backtitle "$BACKTITLE" --title "$TITLE" \
            --yes-label "Reboot" \
            --no-label "Shell" \
            --yesno "RouterOS has been successfully installed to $TARGET_DISK!\n\n[IMPORTANT] Please remove the CD-ROM or USB installation media before rebooting.\n\nDo you want to reboot the system now?\n\n- Select [Reboot] to restart system\n- Select [Shell] to exit to terminal" 14 70
        local post_rc=$?
        if [[ $post_rc -eq 0 ]]; then
            echo "Rebooting system..."
            reboot
        else
            echo "Installation completed. Returned to shell."
            exit 0
        fi
    else
        # Installation Failure
        local err_detail="${LAST_ERROR}"
        if [[ -f "$LOG_FILE" ]]; then
            local tail_log=$(tail -n 6 "$LOG_FILE" 2>/dev/null)
            [[ -n "$tail_log" ]] && err_detail+="\n\nRecent Log Details:\n$tail_log"
        fi

        dialog --backtitle "$BACKTITLE" --title "Installation Failed" \
            --yes-label "Reboot" \
            --no-label "Shell" \
            --yesno "RouterOS installation failed!\n\nReason:\n$err_detail\n\nPlease select next action:" 16 72
        local post_rc=$?
        if [[ $post_rc -eq 0 ]]; then
            echo "Rebooting system..."
            reboot
        else
            echo "Installation failed. Returned to shell. Log file: $LOG_FILE"
            exit 1
        fi
    fi
}

main "$@"
