#!/bin/bash
# Requires bash >= 4: mapfile, associative arrays (declare -A).
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: this installer requires bash >= 4 (found $BASH_VERSION)." >&2
    exit 1
fi

BACKTITLE="MikroTik RouterOS LiveCD Installer"
TITLE="RouterOS Installation Wizard"
TITLE_SCAN="1/6  Scan Installation Media"
TITLE_SOURCE="2/6  Select Installation Source"
TITLE_PACKAGES="3/6  Select Packages"
TITLE_DISK="4/6  Select Target Disk"
TITLE_EXISTING="5/6  Existing Installation"
TITLE_CONFIRM="6/6  Confirm Installation"
TITLE_INSTALL="Installing RouterOS"

WORK_DIR="${WORK_DIR:-/tmp/ros_install}"
BUILD_DIR="$WORK_DIR/build"
BACKUP_DIR="$WORK_DIR/rw_backup"
BOOT_MNT="$WORK_DIR/mnt_boot"
ROS_MNT="$WORK_DIR/mnt_ros"
PROBE_MNT="$WORK_DIR/mnt_probe"
LOG_FILE="$WORK_DIR/install.log"
SOURCES_FILE="$WORK_DIR/sources.txt"
RC_FILE="$WORK_DIR/rc.txt"
ERR_FILE="$WORK_DIR/err.txt"

NPK_DIR=""
SOURCE_DIR=""
NPK_SOURCE_DIRS=()
MAIN_NPK=""
COMP_NPK_LIST=()
SELECTED_PACKAGES=()
TARGET_DISK=""
KEEP_CONFIG="no"
EXISTING_ROS_PART=""
LAST_ERROR=""

# Non-matching globs expand to nothing (zsh (N) qualifier equivalent)
shopt -s nullglob

# ------------------------------------------------------------------------------
# Helper functions: Logging & Cleanup
# ------------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# All dialogs go through this wrapper: --erase-on-exit makes dialog wipe its
# own window on exit, so no leftovers garble the next dialog drawn over it.
dlg() {
    dialog --erase-on-exit --backtitle "$BACKTITLE" "$@"
}

# Progress line for the programbox/progressbox consumers. Never fails the
# caller (ERR_EXIT friendly) and tolerates a closed pipe (Esc on the dialog).
step_msg() {
    printf '%s\n' "$*" || true
}

cleanup_mounts() {
    sync
    umount "$BOOT_MNT" 2>/dev/null || true
    umount "$ROS_MNT" 2>/dev/null || true
    if [[ -d "$PROBE_MNT" ]]; then
        local m
        for m in "$PROBE_MNT"/*/; do
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
    local name
    name=$(basename "$dev")

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
    local name
    name=$(basename "$dev")

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
    local realdev mntdev
    realdev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")

    # Compare against the first field of each /proc/mounts line (the device)
    while read -r mntdev _; do
        if [[ "$mntdev" == "$realdev" || "$mntdev" == "$dev" ]]; then
            return 0
        fi
    done < /proc/mounts
    return 1
}

# ------------------------------------------------------------------------------
# Discover and Mount Installation Media
# ------------------------------------------------------------------------------
discover_and_mount_media() {
    local dev realdev target_mnt b

    mkdir -p /media/cdrom /media/usb "$PROBE_MNT"

    # 1. Check optical drives (/dev/sr0, /dev/cdrom, etc.)
    for dev in /dev/sr[0-9]* /dev/cdrom*; do
        [[ -b "$dev" ]] || continue

        is_device_mounted "$dev" && continue

        realdev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")
        is_device_mounted "$realdev" && continue

        target_mnt="/media/cdrom"
        if grep -q " /media/cdrom " /proc/mounts 2>/dev/null; then
            target_mnt="$PROBE_MNT/$(basename "$realdev")"
        fi
        mkdir -p "$target_mnt"

        mount -t iso9660 -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t udf -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || \
        mount -o ro "$realdev" "$target_mnt" >/dev/null 2>&1 || true
    done

    # 2. Scan block devices from /sys/class/block/ (USB flash drives, etc.)
    for b in /sys/class/block/*; do
        dev="/dev/$(basename "$b")"
        [[ -b "$dev" ]] || continue

        # Optical drives (sr*/cdrom*) are owned by the loop above; never
        # mount them onto the USB mount point. Name-based check only: an
        # isohybrid USB stick (sd* with iso9660) must still be handled here.
        [[ "$(basename "$dev")" =~ ^(sr|cdrom) ]] && continue

        is_cdrom_or_usb "$dev" || continue

        is_device_mounted "$dev" && continue

        realdev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")
        is_device_mounted "$realdev" && continue

        target_mnt="$PROBE_MNT/$(basename "$realdev")"
        if ! grep -q " /media/usb " /proc/mounts 2>/dev/null; then
            target_mnt="/media/usb"
        fi
        mkdir -p "$target_mnt"

        mount -o ro "$dev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t iso9660 -o ro "$dev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t udf -o ro "$dev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t vfat -o ro "$dev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t ext4 -o ro "$dev" "$target_mnt" >/dev/null 2>&1 || \
        mount -t ntfs -o ro "$dev" "$target_mnt" >/dev/null 2>&1 || true
    done
}

get_media_dirs() {
    local dev mnt rest d
    local -a dirs
    declare -A seen=()

    # Inspect all currently mounted directories from /proc/mounts
    while read -r dev mnt rest; do
        [[ -n "$dev" ]] || continue
        [[ -d "$mnt" ]] || continue
        [[ "$mnt" == "/" || "$mnt" == "/proc"* || "$mnt" == "/sys"* || "$mnt" == "/dev"* ]] && continue

        if is_cdrom_or_usb "$dev" || [[ "$mnt" =~ ^(/media|/cdrom|/mnt|/run/media|"$PROBE_MNT") ]]; then
            [[ -z "${seen[$mnt]}" ]] && { seen[$mnt]=1; dirs+=("$mnt"); }
        fi
    done < /proc/mounts

    # Emit one mount point per line
    for d in "${dirs[@]}"; do
        printf '%s\n' "$d"
    done
}

# One canonical glob list for "where NPK files can live under a media dir".
# Every caller (scan, source menu, classification) uses the same patterns:
# the media dir itself, one level below it, and packages/ (depth 2).
npk_glob_results() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0
    find "$dir" -maxdepth 2 -type f -name '*.npk' 2>/dev/null | LC_ALL=C sort
}

# Return the routeros-*.npk system package of a media dir (empty if none).
find_main_npk_in() {
    local dir="$1" npk_file
    while IFS= read -r npk_file; do
        [[ -z "$npk_file" ]] && continue
        [[ "$(basename "$npk_file")" == routeros-*.npk ]] && { printf '%s\n' "$npk_file"; return 0; }
    done < <(npk_glob_results "$dir")
    return 0
}

# ------------------------------------------------------------------------------
# Classify NPK files found under one media source dir into the main system
# package (routeros-*.npk) and component packages (everything else).
#   MAIN_NPK / COMP_NPK_LIST are set from the files of this source only
# ------------------------------------------------------------------------------
classify_npk_files() {
    local npk_file bn tag
    declare -A seen_tags=()

    MAIN_NPK=""
    COMP_NPK_LIST=()

    for npk_file in "$@"; do
        [[ -z "$npk_file" ]] && continue
        bn=$(basename "$npk_file")
        case "$bn" in
            routeros-*.npk)
                [[ -z "$MAIN_NPK" ]] && MAIN_NPK="$npk_file"
                ;;
            *)
                tag="${bn%.npk}"
                tag="${tag%-[0-9]*}"
                if [[ -z "${seen_tags[$tag]}" ]]; then
                    seen_tags[$tag]=1
                    COMP_NPK_LIST+=("$npk_file")
                fi
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Step 1/6: Scan & Mount Media for NPK packages
# Runs inside a subshell piped into a dialog --progressbox. Writes one source
# dir per line into $SOURCES_FILE; exit code 0 = at least one valid source.
# ------------------------------------------------------------------------------
scan_media_npk() {
    local m npk_file main_npk has_main
    local -a media_dirs npk_files
    declare -A seen_sources=()

    : > "$SOURCES_FILE"

    step_msg "Mounting CD-ROM and USB devices..."
    discover_and_mount_media
    log "Media discovery finished"

    mapfile -t media_dirs < <(get_media_dirs)
    log "Found media directories to scan: ${media_dirs[*]}"

    if [[ ${#media_dirs[@]} -eq 0 ]]; then
        step_msg "No CD-ROM or USB device detected."
        return 1
    fi

    step_msg "Searching for RouterOS packages (*.npk)..."
    for m in "${media_dirs[@]}"; do
        step_msg "Scanning $m"
        has_main=0
        main_npk=""
        mapfile -t npk_files < <(npk_glob_results "$m")
        for npk_file in "${npk_files[@]}"; do
            [[ -z "$npk_file" ]] && continue
            log "Found NPK: $npk_file"
            if [[ "$(basename "$npk_file")" == routeros-*.npk ]]; then
                has_main=1
                main_npk="$npk_file"
            fi
        done
        # Only media containing a routeros-*.npk system package are valid sources
        if [[ $has_main -eq 1 ]]; then
            if [[ -z "${seen_sources[$m]}" ]]; then
                seen_sources[$m]=1
                printf '%s\n' "$m" >> "$SOURCES_FILE"
                step_msg "  -> valid source: $(basename "$main_npk")"
            fi
        fi
    done

    if [[ ! -s "$SOURCES_FILE" ]]; then
        step_msg "No RouterOS system image (routeros-*.npk) found."
        log "No media with routeros-*.npk found on scanned media"
        return 1
    fi

    step_msg "Scan complete."
    return 0
}

step_scan() {
    while :; do
        NPK_SOURCE_DIRS=()

        : > "$RC_FILE"
        ( scan_media_npk; echo $? > "$RC_FILE" ) \
            | dlg --title "$TITLE_SCAN" --progressbox "Scanning installation media..." 14 72

        if [[ $(<"$RC_FILE") == 0 ]]; then
            mapfile -t NPK_SOURCE_DIRS < "$SOURCES_FILE"
            return 0
        fi

        # No valid source found on any media
        dlg --title "$TITLE_SCAN" \
            --yes-label "Retry" \
            --no-label "Exit" \
            --yesno "No RouterOS system image (routeros-*.npk) was found on CD-ROM or USB media.\n\nPlease insert the installation media and try again.\n\nSelect [Retry] to rescan, or [Exit] to cancel and return to the shell." 13 70
        if [[ $? -eq 0 ]]; then
            continue
        else
            return 255
        fi
    done
}

# ------------------------------------------------------------------------------
# Step 2/6: Select Installation Source
# Auto-selects a single source; shows a menu otherwise. Back returns to scan.
# ------------------------------------------------------------------------------
step_source() {
    # Single source: auto-select without a dialog
    if [[ ${#NPK_SOURCE_DIRS[@]} -eq 1 ]]; then
        SOURCE_DIR="${NPK_SOURCE_DIRS[0]}"
        log "Single installation source: $SOURCE_DIR"
        return 0
    fi

    local -a menu_items
    local m main_npk
    for m in "${NPK_SOURCE_DIRS[@]}"; do
        main_npk=$(find_main_npk_in "$m")
        menu_items+=("$m" "$(basename "$main_npk")")
    done

    local choice
    choice=$(dlg --stdout --title "$TITLE_SOURCE" \
        --ok-label "Next" \
        --cancel-label "Back" \
        --extra-button --extra-label "Exit" \
        --menu "Multiple installation sources were detected.\n\nSelect the media to install RouterOS from:" 16 74 6 \
        "${menu_items[@]}")
    local rc=$?

    case $rc in
        0)
            SOURCE_DIR="$choice"
            log "User selected installation source: $SOURCE_DIR"
            return 0
            ;;
        1)
            return 1   # Back -> step 1 (rescan)
            ;;
        3)
            return 3   # Exit
            ;;
        *)
            return 255  # Exit (Esc)
            ;;
    esac
}

# Is the given package tag in SELECTED_PACKAGES?
pkg_selected() {
    local t
    for t in "${SELECTED_PACKAGES[@]}"; do
        [[ "$t" == "$1" ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------------------------
# Step 3/6: Component Package Selection
# ------------------------------------------------------------------------------
step_packages() {
    if [[ ${#COMP_NPK_LIST[@]} -eq 0 ]]; then
        dlg --title "$TITLE_PACKAGES" \
            --ok-label "OK" \
            --extra-button --extra-label "Back" \
            --msgbox "No optional packages were found on the installation media.\n\nOnly the base system will be installed.\n\nSystem package: $(basename "$MAIN_NPK")" 11 70
        local rc=$?
        case $rc in
            0) return 0 ;;      # OK
            *) return 1 ;;      # Back (extra button) or Esc
        esac
    fi

    local -a check_items
    declare -A added_tags=()
    local npk_file bn tag is_on
    for npk_file in "${COMP_NPK_LIST[@]}"; do
        bn=$(basename "$npk_file")
        tag="${bn%.npk}"
        tag="${tag%-[0-9]*}"

        # Strictly ensure unique tags
        [[ -n "${added_tags[$tag]}" ]] && continue
        added_tags[$tag]=1

        is_on="ON"
        if [[ ${#SELECTED_PACKAGES[@]} -gt 0 ]]; then
            if pkg_selected "$tag"; then
                is_on="ON"
            else
                is_on="OFF"
            fi
        fi
        check_items+=("$tag" "$bn" "$is_on")
    done

    local choice
    choice=$(dlg --stdout --title "$TITLE_PACKAGES" \
        --separate-output \
        --ok-label "Next" \
        --cancel-label "Back" \
        --extra-button --extra-label "Exit" \
        --checklist "Select the optional component packages to install.\n\nUse SPACE to toggle an entry, TAB to move between the list and buttons." 18 72 8 \
        "${check_items[@]}")
    local rc=$?

    log "step_packages returned code: $rc, choice: ${choice:-<empty>}"

    case $rc in
        0)
            SELECTED_PACKAGES=()
            if [[ -n "$choice" ]]; then
                mapfile -t SELECTED_PACKAGES <<< "$choice"
            fi
            log "Selected packages: ${SELECTED_PACKAGES[*]}"
            return 0
            ;;
        1)
            # Back to step 2
            return 1
            ;;
        3|255)
            # Exit wizard
            return 255
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Step 4/6: Target Disk Selection
# ------------------------------------------------------------------------------
step_disk() {
    local -a menu_items
    local dev size type model devname desc

    # Scan all disk block devices: SATA, SAS, NVMe, VirtIO (vda), Xen (xvda), IDE (hda), eMMC (mmcblk)
    while read -r dev size type model; do
        [[ "$type" == "disk" ]] || continue

        devname=$(basename "$dev")
        # Exclude RAM, Loop, ZRAM, and optical CD-ROM devices
        [[ "$devname" =~ ^(loop|ram|zram|sr) ]] && continue

        # Exclude USB flash drives and USB installation media
        if is_cdrom_or_usb "$dev"; then
            continue
        fi

        # Construct friendly description
        desc="${size}"
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
        dlg --title "$TITLE_DISK" \
            --msgbox "No usable target hard disk was found.\n\nUSB drives and CD-ROM drives are excluded from the list of target disks." 11 62
        return 1
    fi

    local choice
    choice=$(dlg --stdout --title "$TITLE_DISK" \
        --ok-label "Next" \
        --cancel-label "Back" \
        --extra-button --extra-label "Exit" \
        --menu "Select the target disk for the RouterOS installation.\n\nWARNING: ALL EXISTING DATA ON THE SELECTED DISK WILL BE ERASED!" 18 74 7 \
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
# Step 5/6: Existing Installation & Config Retention
# ------------------------------------------------------------------------------
step_existing() {
    EXISTING_ROS_PART=""
    local candidate dev

    # Preferred: the partition we label "RouterOS" ourselves; still verify /rw/store
    candidate=$(blkid -L "RouterOS" 2>/dev/null | head -n 1)
    mkdir -p "$ROS_MNT"
    if [[ -n "$candidate" ]]; then
        if mount -o ro "$candidate" "$ROS_MNT" 2>/dev/null; then
            [[ -f "$ROS_MNT/rw/store" ]] && EXISTING_ROS_PART="$candidate"
            umount "$ROS_MNT" 2>/dev/null || true
        fi
    fi

    # Fallback: probe every block device for an existing RouterOS layout
    if [[ -z "$EXISTING_ROS_PART" ]]; then
        for dev in $(lsblk -p -o NAME -n 2>/dev/null | grep -E '^/dev/'); do
            if mount -o ro "$dev" "$ROS_MNT" 2>/dev/null; then
                if [[ -f "$ROS_MNT/rw/store" ]]; then
                    EXISTING_ROS_PART="$dev"
                    umount "$ROS_MNT" 2>/dev/null || true
                    break
                fi
                umount "$ROS_MNT" 2>/dev/null || true
            fi
        done
    fi

    if [[ -n "$EXISTING_ROS_PART" ]]; then
        dlg --title "$TITLE_EXISTING" \
            --yes-label "Keep Config" \
            --no-label "Clean Install" \
            --extra-button --extra-label "Back" \
            --yesno "An existing RouterOS installation was detected on $EXISTING_ROS_PART.\n\nDo you want to keep the existing configuration?\n\nSelect [Keep Config] to back up /rw and restore it after installation, or [Clean Install] to discard it and start fresh." 15 70
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
                # Back to step 4
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
# Step 6/6: Installation Summary & Execution
# ------------------------------------------------------------------------------
step_install() {
    # Detect boot mode early so it can be shown in the summary
    local boot_mode="BIOS/Legacy"
    if [[ -d /sys/firmware/efi ]]; then
        boot_mode="UEFI"
    fi
    log "Boot mode: $boot_mode"

    local pkgs_str="None (base system only)"
    if [[ ${#SELECTED_PACKAGES[@]} -gt 0 ]]; then
        pkgs_str=$(IFS=', '; echo "${SELECTED_PACKAGES[*]}")
    fi

    local summary="Please review the installation settings:\n\n"
    summary+="  Source media    : $NPK_DIR\n"
    summary+="  System package  : $(basename "$MAIN_NPK")\n"
    summary+="  Components      : $pkgs_str\n"
    summary+="  Target disk     : $TARGET_DISK\n"
    summary+="  Boot mode       : $boot_mode\n"
    summary+="  Keep config     : $KEEP_CONFIG\n\n"
    summary+="WARNING: $TARGET_DISK will be partitioned and formatted.\nALL DATA ON THIS DISK WILL BE PERMANENTLY DESTROYED!"

    dlg --title "$TITLE_CONFIRM" \
        --yes-label "Install" \
        --no-label "Back" \
        --extra-button --extra-label "Exit" \
        --yesno "$summary" 17 72
    local rc=$?
    case $rc in
        0) ;; # Proceed with installation
        1) return 1 ;; # Back to step 5
        3|255) return 255 ;; # Exit
    esac

    # Start Installation
    # Truncate the handshake files but keep appending to $LOG_FILE so the
    # scan/source selections from earlier steps stay available for debugging.
    : >> "$LOG_FILE"
    log "--- Installation starting ---"
    : > "$RC_FILE"
    : > "$ERR_FILE"

    # Execution Routine. Runs in a subshell piped into a dialog --programbox:
    # progress lines go to stdout (the pipe), command output to the log file.
    do_install_process() {
        # If the user closes the dialog early (Esc), the pipe reader is gone;
        # ignore SIGPIPE so the installation itself is not killed mid-way.
        trap '' PIPE
        # Note: no `set -e`/ERR trap here. Every critical command below is
        # explicitly guarded with `if ! ... || { ...; return 1 }` and writes
        # its own reason to $ERR_FILE; an ERR trap would fire on the guarded
        # command itself and clobber the specific message with a generic one.
        trap - ERR
        set +e

        # 1. Environment prep & config backup
        step_msg "[  5%] Step 1/8: Initializing environment..."
        log "Step 1: Init environment"
        cleanup_mounts
        mkdir -p "$BUILD_DIR" "$BACKUP_DIR" "$BOOT_MNT" "$ROS_MNT"
        rm -rf "$BUILD_DIR/sq"

        if [[ "$KEEP_CONFIG" == "yes" && -n "$EXISTING_ROS_PART" ]]; then
            step_msg "[ 10%] Step 1/8: Backing up existing configuration (/rw)..."
            log "Backing up config from $EXISTING_ROS_PART"
            mkdir -p "$ROS_MNT"
            if mount -o ro "$EXISTING_ROS_PART" "$ROS_MNT" 2>/dev/null; then
                rm -rf "$BACKUP_DIR/rw"
                mkdir -p "$BACKUP_DIR/rw"
                cp -a "$ROS_MNT/rw/." "$BACKUP_DIR/rw/" 2>/dev/null || true
                umount "$ROS_MNT" 2>/dev/null || true
                log "Config backup finished"
                step_msg "[ 12%] Step 1/8: Environment ready & config backed up"
            else
                log "Warning: Could not mount $EXISTING_ROS_PART to backup /rw"
                step_msg "[ 12%] Step 1/8: Environment ready (config backup skipped)"
            fi
        else
            step_msg "[ 12%] Step 1/8: Environment & modules initialized"
        fi

        # 2. Extract NPK FILE_CONTAINER (bootloader, milo, EFI files)
        step_msg "[ 18%] Step 2/8: Extracting NPK FILE_CONTAINER (boot files)..."
        log "Step 2: Extracting NPK FILE_CONTAINER from $MAIN_NPK"
        local sq="$BUILD_DIR/sq"
        rm -rf "$sq" && mkdir -p "$sq"

        local npkextract_bin
        npkextract_bin=$(command -v npkextract 2>/dev/null || echo "")
        if [[ -z "$npkextract_bin" ]]; then
            step_msg "[ 18%] [ERR] Step 2/8: npkextract not found in PATH"
            echo "npkextract is required but not found. Please ensure it is installed in the LiveCD." > "$ERR_FILE"
            return 1
        fi

        log "Using npkextract: $npkextract_bin"
        if ! "$npkextract_bin" "$MAIN_NPK" "$sq" >> "$LOG_FILE" 2>&1; then
            step_msg "[ 18%] [ERR] Step 2/8: npkextract failed on $MAIN_NPK"
            echo "npkextract failed to extract FILE_CONTAINER from $MAIN_NPK" > "$ERR_FILE"
            return 1
        fi

        # Verify key boot files were extracted
        if [[ ! -f "$sq/bin/milo" && ! -f "$sq/boot/EFI/BOOT/BOOTX64.EFI" ]]; then
            step_msg "[ 18%] [ERR] Step 2/8: No boot files found after extraction"
            echo "npkextract ran but neither milo nor BOOTX64.EFI was found in the NPK" > "$ERR_FILE"
            return 1
        fi

        log "Extracted: milo=$(test -f "$sq/bin/milo" && echo yes || echo no), EFI=$(test -f "$sq/boot/EFI/BOOT/BOOTX64.EFI" && echo yes || echo no)"
        step_msg "[ 25%] Step 2/8: Boot files extracted (milo + EFI ready)"

        # Boot mode was detected in step_install (shown in summary); derive flag
        local is_uefi=0
        [[ "$boot_mode" == "UEFI" ]] && is_uefi=1

        # 3. Disk partitioning
        step_msg "[ 32%] Step 3/8: Partitioning $TARGET_DISK ..."
        log "Step 3: Partitioning $TARGET_DISK (boot mode: $boot_mode)"

        wipefs --all --force "$TARGET_DISK" >> "$LOG_FILE" 2>&1

        local SECTORS=$(blockdev --getsz "$TARGET_DISK")
        local LBA_END=$(( (SECTORS - 4096) / 8 * 8 - 1 ))
        if ! sgdisk \
            --set-alignment=1 \
            --new=1:34:65535 --typecode=1:EF00 --change-name=1:"RouterOS Boot" \
            --new=2:65536:$LBA_END --typecode=2:8300 --change-name=2:"RouterOS" \
            --hybrid=1:2:EE \
            "$TARGET_DISK" >> "$LOG_FILE" 2>&1; then
            step_msg "[ 32%] [ERR] Step 3/8: sgdisk failed on $TARGET_DISK"
            echo "sgdisk failed on $TARGET_DISK" > "$ERR_FILE"
            return 1
        fi

        # Active boot partition
        printf '\x80' | dd of="$TARGET_DISK" bs=1 seek=446 conv=notrunc >> "$LOG_FILE" 2>&1 || {
            step_msg "[ 33%] [ERR] Step 3/8: Failed to Active boot partition on $TARGET_DISK"
            echo "dd failed to Active boot partition on $TARGET_DISK" > "$ERR_FILE"
            return 1
        }

        # Must be 0x83, otherwise "ERROR: could not find disk!"
        printf '\x83' | dd of="$TARGET_DISK" bs=1 seek=450 conv=notrunc >> "$LOG_FILE" 2>&1 || {
            step_msg "[ 33%] [ERR] Step 3/8: Failed to change partition type on $TARGET_DISK"
            echo "dd failed to change partition type on $TARGET_DISK" > "$ERR_FILE"
            return 1
        }

        if [[ $is_uefi -eq 0 ]]; then
            # Write MikroTik BIOS bootstrap code into bytes 0-439 of the saved MBR
            printf '%s' "FA31C08ED0BC007C89E65007501FFBFCBF0006B90001F2A5EA1D060000BEBE07B304803C807423803C00750983C610FECB75EFCD18BE9B06AC3C00740B56BB0700B40ECD105EEBF0EBFE8B148B4C0289F5BF0500BB007CB8010257CD135F730C31C0CD134F75EDBE7C06EBCCBFFE7D813D55AA75C289EEEA007C00004572726F72206C6F6164696E67206F7065726174696E6720737973746566D004D697373696E67206F7065726174696E672073797374656D0000000000" \
                | xxd -r -p \
                | dd of="$TARGET_DISK" bs=1 conv=notrunc >> "$LOG_FILE" 2>&1 || {
                    step_msg "[ 33%] [ERR] Step 3/8: Failed to write MBR bootstrap code"
                    echo "Failed to write MikroTik BIOS bootstrap into MBR" > "$ERR_FILE"
                    return 1
                }
        fi
        log "MBR written to $TARGET_DISK"

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
        local p wait_count pname maj_min
        for p in "$bootp" "$rosp"; do
            wait_count=0
            # ~10s: partprobe/udev can take a while on large or slow disks
            while [[ ! -b "$p" && $wait_count -lt 50 ]]; do
                sleep 0.2
                wait_count=$(( wait_count + 1 ))
                mdev -s 2>/dev/null || true

                pname=$(basename "$p")
                if [[ -f "/sys/class/block/$pname/dev" ]]; then
                    maj_min=$(cat "/sys/class/block/$pname/dev")
                    mknod "$p" b "${maj_min%%:*}" "${maj_min#*:}" 2>/dev/null || true
                fi
            done
            if [[ ! -b "$p" ]]; then
                step_msg "[ 35%] [ERR] Step 3/8: Partition device node $p missing"
                echo "Partition device node $p was not created by kernel" > "$ERR_FILE"
                return 1
            fi
        done
        step_msg "[ 45%] Step 3/8: Partitioned $TARGET_DISK (Boot 32M + System)"

        # 4. Format partitions
        if [[ $is_uefi -eq 0 ]]; then
            step_msg "[ 48%] Step 4/8: Formatting $bootp (EXT2) & $rosp (EXT4)..."
            log "Step 4: Formatting $bootp (ext2) and $rosp (ext4)"
            if ! mkfs.ext2 -F -m 0 -b 4096 -L "RouterOS Boot" "$bootp" >> "$LOG_FILE" 2>&1; then
                step_msg "[ 48%] [ERR] Step 4/8: Failed to format Boot partition ($bootp)"
                echo "mkfs.ext2 failed to format Boot partition $bootp" > "$ERR_FILE"
                return 1
            fi
        else
            step_msg "[ 48%] Step 4/8: Formatting $bootp (FAT) & $rosp (EXT4)..."
            log "Step 4: Formatting $bootp (vfat) and $rosp (ext4)"
            if ! mkfs.vfat -F 16 -n "Boot" "$bootp" >> "$LOG_FILE" 2>&1; then
                step_msg "[ 48%] [ERR] Step 4/8: Failed to format Boot partition ($bootp)"
                echo "mkfs.vfat failed to format Boot partition $bootp" > "$ERR_FILE"
                return 1
            fi
        fi
        if ! mkfs.ext4 -F -m 0 -b 4096 -L "RouterOS" "$rosp" >> "$LOG_FILE" 2>&1; then
            step_msg "[ 48%] [ERR] Step 4/8: Failed to format RouterOS partition ($rosp)"
            echo "mkfs.ext4 failed to format RouterOS partition $rosp" > "$ERR_FILE"
            return 1
        fi

        step_msg "[ 58%] Step 4/8: Formatted $bootp & $rosp"

        # 5. Mount and prepare system dirs
        step_msg "[ 62%] Step 5/8: Mounting partitions & creating system layout..."
        log "Step 5: Mounting and creating dirs"
        mkdir -p "$BOOT_MNT" "$ROS_MNT"

        if ! mount "$bootp" "$BOOT_MNT" >> "$LOG_FILE" 2>&1; then
            step_msg "[ 62%] [ERR] Step 5/8: Failed to mount Boot partition ($bootp)"
            echo "Failed to mount Boot partition $bootp to $BOOT_MNT" > "$ERR_FILE"
            return 1
        fi

        if ! mount -t ext4 "$rosp" "$ROS_MNT" >> "$LOG_FILE" 2>&1; then
            step_msg "[ 62%] [ERR] Step 5/8: Failed to mount RouterOS partition ($rosp)"
            echo "Failed to mount RouterOS partition $rosp to $ROS_MNT" > "$ERR_FILE"
            return 1
        fi

        mkdir -p "$ROS_MNT/var/pdb/system" "$ROS_MNT/bin" "$ROS_MNT/boot"
        step_msg "[ 70%] Step 5/8: Partitions mounted & directories created"

        # 6. Install bootloader (EFI & Milo, using is_uefi detected above)
        step_msg "[ 73%] Step 6/8: Installing bootloader..."
        log "Step 6: Installing bootloader (boot mode: $boot_mode)"
        # Install milo to $ROS_MNT/bin/milo (used by both BIOS and UEFI)
        if [[ -f "$sq/bin/milo" ]]; then
            cp -a "$sq/bin/." "$ROS_MNT/bin/" 2>> "$LOG_FILE" || {
                step_msg "[ 73%] [ERR] Step 6/8: Failed to copy milo to $ROS_MNT/bin/"
                echo "Failed to copy milo to $ROS_MNT/bin/milo" > "$ERR_FILE"
                return 1
            }
            chmod 755 "$ROS_MNT/bin/milo"
            log "Copied milo to $ROS_MNT/bin/milo"
        else
            log "Warning: milo not found in extracted NPK at $sq/bin/milo"
        fi

        # Copy the entire boot/ tree (EFI dir, boot map) to BOOT_MNT
        if [[ -d "$sq/boot" ]]; then
            rm -f "$sq/boot/map" 2>> "$LOG_FILE"
            cp -a "$sq/boot/." "$BOOT_MNT/" 2>> "$LOG_FILE" || {
                step_msg "[ 73%] [ERR] Step 6/8: Failed to copy boot/ to $BOOT_MNT"
                echo "Failed to copy boot directory to $BOOT_MNT" > "$ERR_FILE"
                return 1
            }
            log "Copied boot/ tree to $BOOT_MNT"
        else
            log "Warning: boot/ directory not found in extracted NPK at $sq/boot"
        fi

        if [[ $is_uefi -eq 0 ]]; then
            # BIOS/Legacy boot: run milo to setup legacy boot sector on BOOT_MNT
            if [[ -f "$ROS_MNT/bin/milo" ]]; then
                log "BIOS mode: running milo $BOOT_MNT to install legacy boot sector"
                "$ROS_MNT/bin/milo" "$BOOT_MNT" >> "$LOG_FILE" 2>&1 || {
                    log "Error: milo returned non-zero (may be non-fatal on some hardware)"
                    return 1
                }
                step_msg "[ 80%] Step 6/8: BIOS boot - Milo legacy boot sector installed"
            else
                log "Error: milo not available for BIOS boot setup"
                step_msg "[ 80%] [ERR] Step 6/8: Failed to install legacy boot sector (milo not found)"
                echo "milo not found: cannot install legacy boot sector" > "$ERR_FILE"
                return 1
            fi
        else
            # UEFI boot: EFI files already in place (BOOTX64.EFI was in boot/EFI/BOOT/)
            log "UEFI mode: EFI bootloader in place at $BOOT_MNT/EFI/BOOT/BOOTX64.EFI - milo setup via EFI not needed"
            step_msg "[ 80%] Step 6/8: UEFI boot - EFI bootloader installed"
        fi

        # 7. Copy system images and components
        step_msg "[ 83%] Step 7/8: Writing $(basename "$MAIN_NPK") and packages..."
        log "Step 7: Writing packages"
        if ! cp "$MAIN_NPK" "$ROS_MNT/var/pdb/system/image" 2>> "$LOG_FILE" || [[ ! -s "$ROS_MNT/var/pdb/system/image" ]]; then
            step_msg "[ 83%] [ERR] Step 7/8: Failed to write system image"
            echo "Failed to copy main package to $ROS_MNT/var/pdb/system/image" > "$ERR_FILE"
            return 1
        fi

        local p src bn comp_file
        for p in "${SELECTED_PACKAGES[@]}"; do
            [[ -z "$p" ]] && continue
            src=""
            for comp_file in "${COMP_NPK_LIST[@]}"; do
                bn=$(basename "$comp_file")
                if [[ "$bn" == ${p}-* || "$bn" == ${p}.npk ]]; then
                    src="$comp_file"
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
        step_msg "[ 90%] Step 7/8: System image & selected components written"

        # 8. Restore config & sync
        step_msg "[ 93%] Step 8/8: Finalizing configuration & syncing disks..."
        log "Step 8: Finalizing & sync"
        mkdir -p "$ROS_MNT/rw/disk"
        printf '#!/bin/sh\n# before RouterOS loader start\n' > "$ROS_MNT/rw/disk/rc.local"
        chmod +x "$ROS_MNT/rw/disk/rc.local" 2>/dev/null || true

        if [[ "$KEEP_CONFIG" == "yes" && -d "$BACKUP_DIR/rw" ]]; then
            log "Restoring backup /rw configuration"
            rm -rf "$ROS_MNT/rw"
            cp -a "$BACKUP_DIR/rw" "$ROS_MNT/rw"
            mkdir -p "$ROS_MNT/rw/disk"
            [[ ! -f "$ROS_MNT/rw/disk/rc.local" ]] && printf '#!/bin/sh\n# before RouterOS loader start\n' > "$ROS_MNT/rw/disk/rc.local"
        fi

        sync
        cleanup_mounts
        step_msg "[100%] Step 8/8: Installation completed successfully!"
        log "Installation succeeded!"
        return 0
    }

    ( do_install_process; echo $? > "$RC_FILE" ) \
        | dlg --title "$TITLE_INSTALL" --programbox "Installing RouterOS - progress log:" 20 76

    local install_rc
    install_rc=$(<"$RC_FILE")
    install_rc=${install_rc:-1}
    if [[ -s "$ERR_FILE" ]]; then
        LAST_ERROR=$(tail -n 1 "$ERR_FILE")
    fi

    if [[ "$install_rc" -eq 0 ]]; then
        return 0
    fi

    LAST_ERROR="${LAST_ERROR:-An unexpected error occurred during installation. Please check install log.}"
    cleanup_mounts
    return 2
}

# ------------------------------------------------------------------------------
# Main wizard state machine
# ------------------------------------------------------------------------------
main() {
    dlg --title "$TITLE" \
        --yes-label "Yes" \
        --no-label "No" \
        --yesno "Welcome to the MikroTik RouterOS Installation Wizard.\n\nDo you want to start the installation now?\n\nSelect [Yes] to continue, or [No] to exit to the shell." 12 62
    local start_rc=$?

    if [[ $start_rc -ne 0 ]]; then
        echo "Cancelled by user. Exiting wizard, returning to shell."
        exit 0
    fi

    mkdir -p "$BUILD_DIR" "$BACKUP_DIR" "$BOOT_MNT" "$ROS_MNT" "$PROBE_MNT"
    local step=1
    local install_result=0
    local rc
    local -a src_files
    local npk_file

    while :; do
        case $step in
            1)
                step_scan
                rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=2
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            2)
                step_source
                rc=$?
                if [[ $rc -eq 0 ]]; then
                    # Classify NPKs restricted to the chosen source
                    src_files=()
                    mapfile -t src_files < <(npk_glob_results "$SOURCE_DIR")
                    classify_npk_files "${src_files[@]}"
                    NPK_DIR=$(dirname "$MAIN_NPK")
                    log "Using source: $SOURCE_DIR, MAIN_NPK: $MAIN_NPK"
                    step=3
                elif [[ $rc -eq 1 ]]; then
                    step=1    # Back -> rescan media
                elif [[ $rc -eq 3 ]]; then
                    echo "Installation wizard cancelled."
                    exit 0
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            3)
                step_packages
                rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=4
                elif [[ $rc -eq 1 ]]; then
                    # Back: to source selection, or straight to scan when the
                    # source was auto-selected (nothing to re-choose there)
                    if [[ ${#NPK_SOURCE_DIRS[@]} -gt 1 ]]; then
                        step=2
                    else
                        step=1
                    fi
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            4)
                step_disk
                rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=5
                elif [[ $rc -eq 1 ]]; then
                    step=3
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            5)
                step_existing
                rc=$?
                if [[ $rc -eq 0 ]]; then
                    step=6
                elif [[ $rc -eq 1 ]]; then
                    step=4
                else
                    echo "Installation wizard cancelled."
                    exit 0
                fi
                ;;
            6)
                step_install
                rc=$?
                if [[ $rc -eq 0 ]]; then
                    install_result=0
                    break
                elif [[ $rc -eq 1 ]]; then
                    step=4
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
        dlg --title "Installation Complete" \
            --yes-label "Reboot" \
            --no-label "Shell" \
            --yesno "RouterOS has been successfully installed to $TARGET_DISK.\n\nIMPORTANT: Remove the installation media (CD-ROM or USB drive) before rebooting.\n\nSelect [Reboot] to restart the system now, or [Shell] to exit to the shell." 14 70
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
            local tail_log
            tail_log=$(tail -n 6 "$LOG_FILE" 2>/dev/null)
            [[ -n "$tail_log" ]] && err_detail+="\n\nRecent Log Details:\n$tail_log"
        fi

        dlg --title "Installation Failed" \
            --yes-label "Reboot" \
            --no-label "Shell" \
            --yesno "RouterOS installation failed.\n\nError details:\n$err_detail\n\nSelect [Reboot] to restart the system, or [Shell] to exit to the shell." 16 72
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
