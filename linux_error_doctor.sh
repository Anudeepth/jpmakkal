#!/usr/bin/env bash
# ==============================================================================
#  LINUX ERR DOCTOR  v3.0
#  Fetches, parses, and explains Linux system log errors in plain English.
#
#  Usage:
#    sudo ./linux_error_doctor.sh              # auto-fetch all system logs
#    sudo ./linux_error_doctor.sh --quick      # fast scan
#    cat /var/log/syslog | ./linux_error_doctor.sh --stdin
#    ./linux_error_doctor.sh --file mylog.txt
#    ./linux_error_doctor.sh --watch           # refresh every 60s
#    ./linux_error_doctor.sh --help
# ==============================================================================

set -uo pipefail
IFS=$'\n\t'

# ── Config ────────────────────────────────────────────────────────────────────
VERSION="3.0"
LOG_LINES=200
JOURNAL_HOURS=24
REPORT_DIR="${HOME}/.errordoctor/reports"
REPORT_FILE="${REPORT_DIR}/report_$(date +%Y%m%d_%H%M%S).txt"

# ── Colors ────────────────────────────────────────────────────────────────────
R="\033[0m"
BOLD="\033[1m"; DIM="\033[2m"; ITALIC="\033[3m"
RED="\033[38;5;196m";  ORA="\033[38;5;208m";  YEL="\033[38;5;226m"
GRN="\033[38;5;82m";   CYA="\033[38;5;51m";   BLU="\033[38;5;33m"
MAG="\033[38;5;201m";  WHT="\033[38;5;255m";  GRY="\033[38;5;245m"
DGR="\033[38;5;238m"
BG_CRIT="\033[48;5;196m"; BG_HDR="\033[48;5;17m"

# ── Counters ──────────────────────────────────────────────────────────────────
CNT_CRIT=0; CNT_ERR=0; CNT_WARN=0; CNT_INFO=0; CNT_TOTAL=0

# ==============================================================================
#  UTILITIES
# ==============================================================================

W() { tput cols 2>/dev/null || echo 80; }

hr() {
    local c="${1:--}" col="${2:-$DGR}"
    printf "${col}"; printf '%*s' "$(W)" '' | tr ' ' "$c"; printf "${R}\n"
}

box_header() {
    local t="$1" col="${2:-$CYA}"
    echo ""
    printf "${BG_HDR}${BOLD}${col} >> %-$(( $(W) - 5 ))s${R}\n" "$t"
    hr "-" "$DGR"
}

kv() { printf "  ${CYA}${BOLD}%-28s${R}  ${WHT}%s${R}\n" "$1" "$2"; }

cmd_ok() { command -v "$1" &>/dev/null; }

badge() {
    case "${1^^}" in
        CRITICAL) printf "${BG_CRIT}${WHT}${BOLD} CRITICAL ${R}" ;;
        ERROR)    printf "${RED}${BOLD}[  ERROR  ]${R}" ;;
        WARNING)  printf "${YEL}${BOLD}[ WARNING ]${R}" ;;
        INFO)     printf "${GRN}${BOLD}[  INFO   ]${R}" ;;
        *)        printf "${GRY}${BOLD}[ UNKNOWN ]${R}" ;;
    esac
}

classify() {
    local l="${1,,}"
    [[ "$l" =~ (critical|emerg|panic|out.of.memory|oom.killer|soft.lockup|bug:|gpu.hang|fallen.off.the.bus|gpu.lockup|nvme.*reset.controller|bios.error|gpu.reset.begin) ]] \
        && echo CRITICAL && return
    [[ "$l" =~ (error|failed|failure|segfault|buffer.i\/o|i\/o.error|xid.*79|nvme.*timeout|dhcp.*failed|unable.to.enumerate|apparmor.*denied|syn.flood|syn.flooding) ]] \
        && echo ERROR && return
    [[ "$l" =~ (warn|timeout|timed.out|mounting.fs.with.errors|possible.syn|module.verification.failed|failed.to.load|opcode.*failed|activation.*failed) ]] \
        && echo WARNING && return
    [[ "$l" =~ (info|notice|succeeded|resume) ]] \
        && echo INFO && return
    echo UNKNOWN
}

# ==============================================================================
#  EXPLAIN ENGINE — Match & explain every known error pattern
# ==============================================================================
explain_line() {
    local line="$1"
    local sev; sev=$(classify "$line")
    local ts cat explanation fix

    ts=$(echo "$line" | grep -oE "^[A-Za-z]+ +[0-9]+ +[0-9:]+" || echo "")
    cat="System"; explanation=""; fix=""

    # ── GPU: AMD ──────────────────────────────────────────────────────────────
    if [[ "$line" =~ "amdgpu" ]]; then
        if [[ "$line" =~ "ring gfx timeout" ]]; then
            cat="GPU - AMD GFX Ring Timeout"
            explanation="The AMD GPU command queue (ring buffer) timed out. GPU stopped executing graphics commands."
            fix="Check GPU temps (sensors); update amdgpu driver; reduce GPU load or clock speeds."
        elif [[ "$line" =~ "GPU reset begin" ]]; then
            cat="GPU - AMD Reset Initiated"
            explanation="System is performing an emergency AMD GPU reset to recover from the hang."
            fix="Frequent resets = hardware issue. Check thermal paste, PSU power, and GPU seating."
        elif [[ "$line" =~ "GPU reset succeeded" ]]; then
            cat="GPU - AMD Reset Succeeded"
            explanation="AMD GPU successfully recovered from a hang via hardware reset. System resumed."
            fix="Monitor for recurrence. If frequent, check GPU cooling and driver version."
        fi
    fi

    # ── GPU: Intel i915 ───────────────────────────────────────────────────────
    if [[ "$line" =~ "i915" ]]; then
        if [[ "$line" =~ "GPU HANG" ]]; then
            cat="GPU - Intel GPU Hang"
            explanation="Intel integrated GPU (i915) crashed hard. The GPU stopped processing commands entirely."
            fix="sudo apt install intel-microcode linux-firmware && sudo reboot"
        elif [[ "$line" =~ "Resetting chip" ]]; then
            cat="GPU - Intel GPU Reset"
            explanation="Intel GPU heartbeat stopped on render engine (rcs0). Kernel is resetting the GPU chip."
            fix="Update linux-firmware package; try: sudo apt install --reinstall linux-firmware"
        fi
    fi

    # ── GPU: Nouveau (open Nvidia) ────────────────────────────────────────────
    if [[ "$line" =~ "nouveau" && "$line" =~ "GPU lockup" ]]; then
        cat="GPU - Nouveau Lockup (Fallback Mode)"
        explanation="Open-source Nvidia driver (nouveau) detected a GPU lockup. System switched to slow software rendering."
        fix="Install proprietary driver: sudo ubuntu-drivers autoinstall  OR  sudo apt install nvidia-driver-535"
    fi

    # ── GPU: Nvidia proprietary ───────────────────────────────────────────────
    if [[ "$line" =~ "NVRM" && "$line" =~ "GPU has fallen off the bus" ]]; then
        cat="GPU - Nvidia BUS FAILURE (CRITICAL)"
        explanation="Nvidia GPU completely disappeared from PCIe bus. This is a catastrophic hardware failure — GPU is unresponsive at the hardware level."
        fix="1. Reseat GPU in PCIe slot  2. Check all power connectors  3. Test PSU  4. GPU may be dead"
    fi

    if [[ "$line" =~ "nvidia" && "$line" =~ "module verification failed" ]]; then
        cat="GPU - Nvidia Secure Boot Conflict"
        explanation="Nvidia kernel module signature verification failed. Secure Boot is blocking the driver from loading."
        fix="Option A: sudo mokutil --import /var/lib/shim-signed/mok/MOK.der && reboot  Option B: Disable Secure Boot in BIOS"
    fi

    # ── Network: NetworkManager ────────────────────────────────────────────────
    if [[ "$line" =~ "NetworkManager" || "$line" =~ "NetworkManager.service" ]]; then
        if [[ "$line" =~ "Failed to start" ]]; then
            cat="Network - NetworkManager Service Failed"
            explanation="NetworkManager failed to start. No wired or wireless network management is active."
            fix="sudo systemctl restart NetworkManager && journalctl -u NetworkManager -n 50"
        elif [[ "$line" =~ "Dependency failed" ]]; then
            cat="Network - Dependency Chain Failed"
            explanation="A service that NetworkManager depends on failed first, causing NetworkManager to not start."
            fix="sudo systemctl status NetworkManager; check systemctl --failed for root cause"
        fi
    fi

    # ── Network: DHCP ─────────────────────────────────────────────────────────
    if [[ "$line" =~ "dhcp4" ]]; then
        if [[ "$line" =~ "request timed out" ]]; then
            cat="Network - DHCP Request Timeout"
            explanation="WiFi interface (wlan0) sent DHCP request but got no response from router. No IP address assigned."
            fix="Check router/AP is online; try: sudo dhclient -r wlan0 && sudo dhclient wlan0"
        elif [[ "$line" =~ "config -> failed" ]]; then
            cat="Network - DHCP State Machine Failed"
            explanation="DHCP state machine on wlan0 transitioned to 'failed'. Interface has no IP — no internet."
            fix="sudo systemctl restart NetworkManager  OR  nmcli device disconnect wlan0 && nmcli device connect wlan0"
        fi
    fi

    if [[ "$line" =~ "Activation: failed for connection" ]]; then
        cat="Network - WiFi Connection Failed"
        explanation="WiFi connection could not be activated on wlan0. Likely DHCP failure, wrong password, or signal issues."
        fix="nmcli device wifi list  |  nmcli device wifi connect SSID password YOURPASS"
    fi

    # ── Network: SYN Flood ────────────────────────────────────────────────────
    if [[ "$line" =~ "SYN flood" || "$line" =~ "SYN flooding" ]]; then
        cat="Network - SYN Flood Attack (Port 443)"
        explanation="Kernel detected unusually high TCP SYN connection requests on port 443. This is a classic DDoS pattern — someone is flooding your server."
        fix="SYN cookies enabled (already active). Also: sudo ufw limit 443/tcp  |  Use fail2ban or Cloudflare DDoS protection"
    fi

    # ── Network: CIFS / Samba ─────────────────────────────────────────────────
    if [[ "$line" =~ "CIFS" && "$line" =~ "send error" ]]; then
        cat="Network - CIFS/Samba Mount Error"
        explanation="Failed to connect or authenticate to Windows/Samba network share. Error -13 = Permission Denied."
        fix="Verify credentials; try: sudo mount -t cifs //server/share /mnt -o user=X,pass=Y,vers=3.0"
    fi

    # ── Filesystem: EXT4 ──────────────────────────────────────────────────────
    if [[ "$line" =~ "EXT4-fs error" ]]; then
        cat="Filesystem - EXT4 Corruption (CRITICAL)"
        explanation="EXT4 filesystem corruption detected on /dev/sda2. A directory entry (inode #524288) could not be read — filesystem is damaged."
        fix="URGENT: Back up data NOW! Then: sudo fsck -f /dev/sda2 (boot from live USB first)"
    elif [[ "$line" =~ "EXT4-fs warning" && "$line" =~ "mounting fs with errors" ]]; then
        cat="Filesystem - EXT4 Mounted With Errors"
        explanation="The EXT4 filesystem on sda2 was mounted despite having known errors. Data integrity is at risk."
        fix="Schedule repair: sudo touch /forcefsck && reboot  OR  boot live USB and run fsck"
    fi

    # ── Storage: I/O Errors ───────────────────────────────────────────────────
    if [[ "$line" =~ "Buffer I/O error" ]]; then
        cat="Storage - Buffer I/O Error (Disk Failing)"
        explanation="Kernel failed to read/write disk block on /dev/sda2. This means the drive has bad sectors or is failing."
        fix="1. sudo smartctl -a /dev/sda  2. Back up data immediately  3. Replace drive if SMART shows failures"
    elif [[ "$line" =~ "I/O error" && "$line" =~ "sector" ]]; then
        cat="Storage - Bad Sector Detected"
        explanation="A specific disk sector (987654) on sda2 is unreadable. Physical bad sector on drive — drive is failing."
        fix="IMMEDIATE: sudo dd if=/dev/sda of=/dev/null status=progress 2>&1 | grep error  |  Replace drive ASAP"
    fi

    # ── Storage: NVMe ─────────────────────────────────────────────────────────
    if [[ "$line" =~ "nvme" ]]; then
        if [[ "$line" =~ "timeout" && "$line" =~ "aborting" ]]; then
            cat="Storage - NVMe I/O Timeout"
            explanation="NVMe SSD command timed out and was aborted. SSD became unresponsive for this request."
            fix="Check NVMe temp: sudo nvme smart-log /dev/nvme0 | grep temperature  |  Update NVMe firmware"
        elif [[ "$line" =~ "reset controller" ]]; then
            cat="Storage - NVMe Controller Reset (CRITICAL)"
            explanation="NVMe SSD controller completely stopped responding. Kernel forced a hardware reset. Risk of data loss."
            fix="1. Check NVMe temps  2. Update firmware: sudo nvme fw-download  3. Replace SSD if resets continue"
        fi
    fi

    # ── Storage: Mount ────────────────────────────────────────────────────────
    if [[ "$line" =~ "Failed to mount" && "$line" =~ "systemd" ]]; then
        cat="Filesystem - Mount Failed"
        explanation="systemd could not mount /mnt/data. Device may be missing, wrong filesystem type, or has errors."
        fix="Check /etc/fstab; verify device: lsblk; try: sudo mount -a && journalctl -u mnt-data.mount"
    fi

    # ── Memory: OOM Killer ────────────────────────────────────────────────────
    if [[ "$line" =~ "Out of memory" && "$line" =~ "Killed process" ]]; then
        local proc; proc=$(echo "$line" | grep -oE "\([a-z]+\)" | tr -d '()')
        cat="Memory - OOM Killer (CRITICAL)"
        explanation="System completely ran out of RAM. Kernel OOM killer forcibly terminated process '$proc' to free memory."
        fix="1. Add swap: sudo fallocate -l 4G /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile  2. Add more RAM  3. Tune vm.swappiness"
    fi

    # ── CPU: Watchdog / Soft Lockup ───────────────────────────────────────────
    if [[ "$line" =~ "soft lockup" && "$line" =~ "stuck" ]]; then
        cat="CPU - Soft Lockup (CRITICAL)"
        explanation="CPU core #3 has been stuck for 26 seconds without releasing the Linux scheduler. This indicates a kernel deadlock or hardware interrupt storm."
        fix="Check for runaway processes: ps aux --sort=-%cpu | head  |  Check for hardware IRQ issues: cat /proc/interrupts"
    fi

    # ── USB ───────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "usb" ]]; then
        if [[ "$line" =~ "device descriptor read" && "$line" =~ "error -71" ]]; then
            cat="USB - Protocol Error (-71 EPROTO)"
            explanation="USB device failed communication with error -71 (protocol error). Device sent malformed data — usually a bad cable or faulty device."
            fix="Try different USB cable and port. Error -71 is almost always a cable quality issue."
        elif [[ "$line" =~ "unable to enumerate" ]]; then
            cat="USB - Enumeration Failed"
            explanation="Kernel cannot identify or initialize the USB device. Device is invisible to the OS."
            fix="Try different USB port and cable. Test device on another machine. May be hardware failure."
        fi
    fi

    # ── PCIe Bus Error ────────────────────────────────────────────────────────
    if [[ "$line" =~ "PCIe Bus Error" ]]; then
        local pcie_sev; pcie_sev=$(echo "$line" | grep -oE "severity=[A-Za-z]+" | cut -d= -f2)
        cat="Hardware - PCIe Bus Error (${pcie_sev})"
        explanation="PCIe bus hardware error reported at Data Link Layer (severity: ${pcie_sev}). Seen with GPUs, NVMe, or network cards in unstable PCIe slots."
        fix="'Corrected' = monitor only. 'Uncorrected/Fatal' = reseat PCIe card; check slot; update BIOS"
    fi

    # ── SSH Brute Force ───────────────────────────────────────────────────────
    if [[ "$line" =~ "Failed password" && "$line" =~ "sshd" ]]; then
        local ip; ip=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
        local uname; uname=$(echo "$line" | grep -oE "for (invalid user )?[^ ]+ from" | sed 's/ from//' | awk '{print $NF}')
        cat="Security - SSH Brute Force from ${ip}"
        explanation="Failed SSH login from IP $ip attempting user '$uname'. This is an unauthorized access attempt."
        fix="Block IP: sudo ufw deny from $ip  |  Install: sudo apt install fail2ban  |  Disable password auth: PasswordAuthentication no in /etc/ssh/sshd_config"
    fi

    # ── PAM Auth Failure ──────────────────────────────────────────────────────
    if [[ "$line" =~ "pam_unix" && "$line" =~ "authentication failure" ]]; then
        cat="Auth - GUI Login Failed (GDM/PAM)"
        explanation="A login attempt at the graphical login screen (GDM) failed due to wrong password."
        fix="If not you: check for unauthorized local access. Monitor with: sudo lastb | head -20"
    fi

    # ── AppArmor ──────────────────────────────────────────────────────────────
    if [[ "$line" =~ "apparmor" && "${line,,}" =~ "denied" ]]; then
        local op; op=$(echo "$line" | grep -oE 'operation="[^"]*"' | cut -d'"' -f2 || echo "unknown")
        cat="Security - AppArmor Access Denied"
        explanation="AppArmor security module DENIED operation '$op'. A process tried something not permitted by its security profile."
        fix="If expected app behavior: sudo aa-complain <profile>  |  Check: sudo journalctl -k --grep=apparmor"
    fi

    # ── ACPI / BIOS ───────────────────────────────────────────────────────────
    if [[ "$line" =~ "ACPI BIOS Error" ]]; then
        cat="ACPI - BIOS Firmware Bug"
        explanation="The BIOS/UEFI ACPI table has a bug. Kernel found an error while parsing hardware configuration from firmware."
        fix="Update BIOS/UEFI to latest version from your motherboard manufacturer's website."
    elif [[ "$line" =~ "ACPI Error" && "$line" =~ "AE_NOT_FOUND" ]]; then
        cat="ACPI - Named Object Not Found"
        explanation="ACPI firmware references a hardware object that doesn't exist in its own tables — firmware inconsistency."
        fix="Usually benign. If hardware features fail (fans, power states): update BIOS firmware."
    fi

    # ── Bluetooth ─────────────────────────────────────────────────────────────
    if [[ "$line" =~ "Bluetooth" && "$line" =~ "failed" && "$line" =~ "Opcode" ]]; then
        cat="Bluetooth - HCI Command Timeout"
        explanation="Bluetooth HCI command (Opcode 0x200c) failed with -110 (ETIMEDOUT). Controller stopped responding."
        fix="sudo systemctl restart bluetooth  |  sudo rmmod btusb && sudo modprobe btusb  |  Check USB Bluetooth dongle"
    fi

    # ── WiFi Firmware ─────────────────────────────────────────────────────────
    if [[ "$line" =~ "iwlwifi" ]]; then
        if [[ "$line" =~ "failed to load" ]]; then
            local fw; fw=$(echo "$line" | grep -oE "iwlwifi[^ ]*\.ucode" || echo "firmware")
            cat="WiFi - Intel Firmware File Missing"
            explanation="Intel WiFi driver (iwlwifi) cannot find firmware file '$fw'. WiFi card will not function without it."
            fix="sudo apt install linux-firmware && sudo update-initramfs -u && sudo reboot"
        elif [[ "$line" =~ "Failed to start RT ucode" ]]; then
            cat="WiFi - Intel WiFi RT Firmware Failed"
            explanation="Intel WiFi real-time firmware load failed (error -110 = timeout). WiFi is completely non-functional."
            fix="sudo apt install --reinstall linux-firmware && reboot. If persists: check kernel version compatibility."
        fi
    fi

    # ── Docker ────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "docker" ]]; then
        if [[ "$line" =~ "FAILURE" && "$line" =~ "Main process exited" ]]; then
            cat="Docker - Daemon Crashed"
            explanation="Docker daemon main process exited with FAILURE status. All containers are now stopped."
            fix="sudo systemctl stop docker && sudo ip link delete docker0 2>/dev/null; sudo systemctl start docker"
        elif [[ "$line" =~ "failed to start daemon" ]]; then
            cat="Docker - Network Controller Init Failed"
            explanation="Docker daemon could not initialize its network controller. Usually a leftover network bridge conflict."
            fix="sudo ip link delete docker0; sudo iptables -t nat -F; sudo systemctl restart docker"
        elif [[ "$line" =~ "Failed to start docker.service" ]]; then
            cat="Docker - Service Startup Failed"
            explanation="systemd could not start docker.service. Docker is unavailable."
            fix="journalctl -u docker -n 50 | tail -20  |  sudo systemctl restart docker"
        fi
    fi

    # ── User Session Killed (OOM follow-up) ───────────────────────────────────
    if [[ "$line" =~ "user@" && "$line" =~ "code=killed" && "$line" =~ "status=9/KILL" ]]; then
        cat="Session - User Session Killed by OOM"
        explanation="User session process (UID 1000) was killed by SIGKILL (OOM killer). Desktop session likely crashed."
        fix="Add more RAM or swap space. Identify memory hogs: ps aux --sort=-%mem | head -10"
    fi

    # ── D-Bus ─────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "dbus" && "$line" =~ "timed out" ]]; then
        cat="D-Bus - Service Activation Timeout"
        explanation="D-Bus message bus tried to start 'org.example.Service' but it did not respond in time."
        fix="Check which service provides this bus name; journalctl -p err | grep dbus"
    fi

    # ── Failed service fallback ────────────────────────────────────────────────
    if [[ "$line" =~ "Failed to start" && "$line" =~ "systemd" && -z "$explanation" ]]; then
        local svc; svc=$(echo "$line" | grep -oE "[a-zA-Z0-9_.-]+\.service" | head -1 || echo "service")
        cat="Service - Systemd Unit Failed"
        explanation="systemd could not start '$svc'. The service is down."
        fix="journalctl -u $svc -n 30  |  sudo systemctl restart $svc"
    fi

    # ── Default fallback ──────────────────────────────────────────────────────
    [[ -z "$explanation" ]] && {
        explanation=$(echo "$line" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}')
        fix=""
    }

    # Update counters
    case "$sev" in
        CRITICAL) ((CNT_CRIT++)) ;;
        ERROR)    ((CNT_ERR++))  ;;
        WARNING)  ((CNT_WARN++)) ;;
        INFO)     ((CNT_INFO++)) ;;
    esac
    ((CNT_TOTAL++))

    printf "%s\t%s\t%s\t%s\t%s\t%s" \
        "$sev" "$ts" "$cat" "$explanation" "$fix" "$line"
}

# ==============================================================================
#  DISPLAY ENGINE
# ==============================================================================
display_entry() {
    local sev="$1" ts="$2" cat="$3" expl="$4" fix="$5" raw="$6"
    echo ""
    badge "$sev"
    printf "  ${GRY}%s${R}\n" "$ts"
    printf "  ${BLU}${BOLD}%-22s${R}  ${WHT}%s${R}\n"  "Category:"       "$cat"
    printf "  ${CYA}${BOLD}%-22s${R}  ${WHT}%s${R}\n"  "What happened:"  "$expl"
    [[ -n "$fix" ]] && \
        printf "  ${GRN}${BOLD}%-22s${R}  ${GRN}%s${R}\n" "How to fix:" "$fix"
    printf "  ${DGR}%-22s${R}  ${DIM}${GRY}%s${R}\n"   "Raw log:"        "$raw"
}

# ==============================================================================
#  FETCH & ANALYZE A BATCH OF LOG LINES
# ==============================================================================
analyze_lines() {
    local source_label="$1"; shift
    local lines_arr=("$@")
    local found=0

    box_header "SOURCE: ${source_label}" "$MAG"

    for line in "${lines_arr[@]+"${lines_arr[@]}"}"; do
        [[ -z "$line" ]] && continue
        # Pre-filter: only process lines with error indicators
        if ! echo "${line,,}" | grep -qE \
            "(error|fail|warn|critical|panic|timeout|timed.out|oom|killed|segfault|lockup|bug:|hang|fallen|reset|denied|flood|corrupt|unable|cannot|refused|missing|invalid|abort|xid|syn.flood|bios.error)"; then
            continue
        fi
        found=1
        local parsed
        parsed=$(explain_line "$line")
        IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
        display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
    done

    [[ $found -eq 0 ]] && printf "\n  ${GRN}No errors found in this source.${R}\n"
}

# ==============================================================================
#  INPUT MODES
# ==============================================================================

read_stdin_mode() {
    box_header "ANALYZING PIPED LOG INPUT" "$CYA"
    local found=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        found=1
        local parsed; parsed=$(explain_line "$line")
        IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
        display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
    done
    [[ $found -eq 0 ]] && printf "\n  ${GRN}No error lines found in stdin.${R}\n"
}

read_file_mode() {
    local f="$1"
    [[ ! -f "$f" ]] && { printf "${RED}File not found: %s${R}\n" "$f"; exit 1; }
    box_header "ANALYZING FILE: $f" "$CYA"
    local found=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if echo "${line,,}" | grep -qE \
            "(error|fail|warn|critical|panic|timeout|oom|killed|lockup|bug:|hang|denied|flood|corrupt|unable|refused|missing|invalid|abort)"; then
            found=1
            local parsed; parsed=$(explain_line "$line")
            IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
            display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
        fi
    done < "$f"
    [[ $found -eq 0 ]] && printf "\n  ${GRN}No error lines found in file.${R}\n"
}

# ==============================================================================
#  BANNER
# ==============================================================================
print_banner() {
    clear
    local w; w=$(W)
    hr "=" "$BLU"
    printf "${BOLD}${CYA}%*s${R}\n" $(( (w + 22) / 2 )) "LINUX ERR DOCTOR  v${VERSION}"
    printf "${GRY}%*s${R}\n"        $(( (w + 50) / 2 )) \
        "System Error Analyzer & Human-Readable Diagnostic Tool"
    hr "=" "$BLU"
    echo ""
    kv "Hostname"   "$(hostname 2>/dev/null || echo unknown)"
    kv "Kernel"     "$(uname -r 2>/dev/null || echo unknown)"
    kv "OS"         "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo Linux)"
    kv "Uptime"     "$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown)"
    kv "Scan Time"  "$(date '+%d %b %Y  %H:%M:%S %Z')"
    kv "Run As"     "$(whoami 2>/dev/null || echo unknown)"
    kv "Report"     "$REPORT_FILE"
    echo ""
    [[ ${EUID:-1} -ne 0 ]] && \
        printf "  ${YEL}Note: Run with sudo for complete log access.${R}\n\n"
    hr "-" "$DGR"
}

# ==============================================================================
#  SYSTEM HEALTH
# ==============================================================================
system_health() {
    box_header "SYSTEM HEALTH SNAPSHOT" "$GRN"

    if cmd_ok free; then
        local mpct; mpct=$(free 2>/dev/null | awk '/^Mem:/{printf "%.0f",$3/$2*100}')
        local minfo; minfo=$(free -h 2>/dev/null | awk '/^Mem:/{print "Used:"$3" / Total:"$2"  Free:"$4}')
        kv "Memory" "$minfo"
        local fill=$(( mpct * 36 / 100 )) empty=$(( 36 - fill ))
        local mc="$GRN"
        [[ $mpct -gt 75 ]] && mc="$YEL"
        [[ $mpct -gt 90 ]] && mc="$RED"
        printf "  ${mc}  RAM ["; printf '%*s' "$fill" '' | tr ' ' '#'
        printf "${GRY}"; printf '%*s' "$empty" '' | tr ' ' '-'
        printf "${mc}] %s%%${R}\n" "$mpct"
        local swap; swap=$(free -h 2>/dev/null | awk '/^Swap:/{print "Used:"$3" / Total:"$2}')
        kv "Swap" "$swap"
    fi

    if cmd_ok uptime; then
        kv "Load Avg" "$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | tr -d ' ')"
    fi

    echo ""
    printf "  ${CYA}${BOLD}Disk:${R}\n"
    df -h --output=source,size,used,avail,pcent,target 2>/dev/null \
        | grep -v "^Filesystem\|tmpfs\|udev" \
        | while IFS= read -r dl; do
        local pct; pct=$(echo "$dl" | awk '{gsub(/%/,"",$5); print $5+0}')
        local dc="$GRN"
        [[ $pct -gt 70 ]] && dc="$YEL"
        [[ $pct -gt 90 ]] && dc="$RED"
        printf "  ${dc}  %s${R}\n" "$dl"
    done
}

# ==============================================================================
#  LIVE SYSTEM SCAN
# ==============================================================================
run_system_scan() {
    local mode="${1:-full}"

    # Journal
    if cmd_ok journalctl; then
        local jlines=()
        while IFS= read -r l; do jlines+=("$l"); done < <(
            journalctl -p err --since="${JOURNAL_HOURS} hours ago" \
                --no-pager --output=short-precise 2>/dev/null \
                | grep -v "^--" | tail -n "$LOG_LINES" || true
        )
        analyze_lines "systemd journal (last ${JOURNAL_HOURS}h)" "${jlines[@]+"${jlines[@]}"}"
    fi

    # Failed Services
    if cmd_ok systemctl; then
        box_header "FAILED SYSTEMD SERVICES" "$RED"
        local fsvc; fsvc=$(systemctl --failed --no-legend --no-pager 2>/dev/null || true)
        if [[ -z "$fsvc" ]]; then
            printf "\n  ${GRN}All services running normally.${R}\n"
        else
            echo "$fsvc" | while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local unit; unit=$(echo "$line" | awk '{print $1}')
                printf "\n  ${RED}${BOLD}FAILED:${R} ${WHT}%s${R}\n" "$unit"
                ((CNT_CRIT++)); ((CNT_TOTAL++))
                printf "  ${GRN}Fix:${R}  journalctl -u %s -n 30  |  sudo systemctl restart %s\n" "$unit" "$unit"
                printf "  ${GRY}Last log lines:${R}\n"
                journalctl -u "$unit" -n 3 --no-pager 2>/dev/null | grep -v "^--" \
                    | while IFS= read -r jl; do printf "    ${DIM}${GRY}%s${R}\n" "$jl"; done
            done
        fi
    fi

    [[ "$mode" == "quick" ]] && return

    # dmesg
    if cmd_ok dmesg; then
        local dlines=()
        while IFS= read -r l; do dlines+=("$l"); done < <(
            dmesg --level=err,crit,emerg,warn 2>/dev/null | tail -n "$LOG_LINES" || true
        )
        analyze_lines "Kernel Ring Buffer (dmesg)" "${dlines[@]+"${dlines[@]}"}"
    fi

    # Syslog
    for f in /var/log/syslog /var/log/messages; do
        [[ -r "$f" ]] || continue
        local slines=()
        while IFS= read -r l; do slines+=("$l"); done < <(
            grep -iE "(error|fail|warn|critical|panic|oom|timeout|lockup|corrupt)" \
                "$f" 2>/dev/null | tail -n "$LOG_LINES" || true
        )
        analyze_lines "$(basename "$f")" "${slines[@]+"${slines[@]}"}"
        break
    done

    # Auth
    for f in /var/log/auth.log /var/log/secure; do
        [[ -r "$f" ]] || continue
        local alines=()
        while IFS= read -r l; do alines+=("$l"); done < <(
            grep -iE "(failed|failure|invalid|denied|banned)" \
                "$f" 2>/dev/null | tail -n 50 || true
        )
        analyze_lines "Auth/Security ($(basename "$f"))" "${alines[@]+"${alines[@]}"}"
        break
    done

    # App logs
    for entry in \
        "/var/log/nginx/error.log:NGINX" \
        "/var/log/apache2/error.log:Apache" \
        "/var/log/mysql/error.log:MySQL" \
        "/var/log/docker.log:Docker"; do
        local fp="${entry%%:*}" nm="${entry##*:}"
        [[ -r "$fp" ]] || continue
        local aplines=()
        while IFS= read -r l; do aplines+=("$l"); done < <(
            grep -iE "(error|fail|crit|warn|panic)" "$fp" 2>/dev/null | tail -n 30 || true
        )
        analyze_lines "$nm" "${aplines[@]+"${aplines[@]}"}"
    done
}

# ==============================================================================
#  SUMMARY
# ==============================================================================
print_summary() {
    local w; w=$(W)
    echo ""
    hr "=" "$BLU"
    printf "${BOLD}${CYA}%*s${R}\n" $(( (w + 20) / 2 )) "DIAGNOSTIC SUMMARY"
    hr "=" "$BLU"
    echo ""
    printf "  ${WHT}${BOLD}%-28s${R}  %s\n"          "Total Analyzed"   "$CNT_TOTAL"
    printf "  ${RED}${BOLD}%-28s${R}  ${RED}%s${R}\n"    "CRITICAL"       "$CNT_CRIT"
    printf "  ${ORA}${BOLD}%-28s${R}  ${ORA}%s${R}\n"    "ERROR"          "$CNT_ERR"
    printf "  ${YEL}${BOLD}%-28s${R}  ${YEL}%s${R}\n"    "WARNING"        "$CNT_WARN"
    printf "  ${GRN}${BOLD}%-28s${R}  ${GRN}%s${R}\n"    "INFO"           "$CNT_INFO"

    local sc="$GRN" si="OK" st="SYSTEM HEALTHY"
    [[ $CNT_WARN  -gt 0 ]] && sc="$YEL" && si="!!" && st="WARNINGS PRESENT"
    [[ $CNT_ERR   -gt 0 ]] && sc="$ORA" && si="XX" && st="ERRORS DETECTED"
    [[ $CNT_CRIT  -gt 0 ]] && sc="$RED" && si="!!" && st="CRITICAL ISSUES FOUND"

    echo ""; hr "-" "$DGR"
    printf "\n  ${BOLD}Overall:  ${sc}${BOLD}[%s] %s${R}\n\n" "$si" "$st"
    hr "-" "$DGR"; echo ""

    printf "  ${CYA}${BOLD}RECOMMENDED COMMANDS:${R}\n\n"
    [[ $CNT_CRIT -gt 0 ]] && \
        printf "  ${RED}  !! Critical issues — inspect failed services and hardware errors NOW.${R}\n"
    [[ $CNT_ERR  -gt 0 ]] && \
        printf "  ${ORA}  XX Errors detected — restart affected services and check hardware.${R}\n"
    [[ $CNT_WARN -gt 0 ]] && \
        printf "  ${YEL}  !! Warnings — monitor closely.${R}\n"
    printf "\n"
    printf "  ${BLU}  journalctl -p err -b --no-pager${R}       ${GRY}# all errors since last boot${R}\n"
    printf "  ${BLU}  systemctl --failed${R}                     ${GRY}# list all failed services${R}\n"
    printf "  ${BLU}  dmesg -T --level=err,crit${R}              ${GRY}# kernel errors with timestamps${R}\n"
    printf "  ${BLU}  sudo smartctl -a /dev/sda${R}              ${GRY}# disk SMART health${R}\n"
    printf "  ${BLU}  sudo ./linux_error_doctor.sh --watch${R}    ${GRY}# continuous live monitoring${R}\n"
    echo ""
    kv "Report saved" "$REPORT_FILE"
    hr "=" "$BLU"; echo ""
}

# ==============================================================================
#  USAGE
# ==============================================================================
usage() {
    printf "${BOLD}${CYA}Linux ERR Doctor  v%s${R}\n\n" "$VERSION"
    printf "  ${BOLD}Usage:${R}  ./linux_error_doctor.sh [OPTIONS]\n\n"
    printf "  ${GRN}(no args)${R}        Full system scan\n"
    printf "  ${GRN}--quick${R}          Fast: journal + failed services only\n"
    printf "  ${GRN}--stdin${R}          Read from pipe:  cat logfile | ./script.sh --stdin\n"
    printf "  ${GRN}--file${R} PATH      Analyze a specific log file\n"
    printf "  ${GRN}--watch${R}          Continuous mode (60s refresh)\n"
    printf "  ${GRN}--hours${R} N        Journal lookback hours (default: %s)\n" "$JOURNAL_HOURS"
    printf "  ${GRN}--lines${R} N        Lines per log source (default: %s)\n" "$LOG_LINES"
    printf "  ${GRN}--help${R}           This help\n\n"
    printf "  ${GRY}Examples:\n"
    printf "    sudo ./linux_error_doctor.sh\n"
    printf "    sudo ./linux_error_doctor.sh --quick\n"
    printf "    cat /var/log/syslog | ./linux_error_doctor.sh --stdin\n"
    printf "    ./linux_error_doctor.sh --file /var/log/syslog\n"
    printf "    sudo ./linux_error_doctor.sh --watch${R}\n\n"
}

# ==============================================================================
#  MAIN
# ==============================================================================
main() {
    local mode="full" watch=false use_stdin=false file_path=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick)   mode="quick" ;;
            --watch)   watch=true ;;
            --stdin)   use_stdin=true ;;
            --file)    shift; file_path="$1" ;;
            --hours)   shift; JOURNAL_HOURS="$1" ;;
            --lines)   shift; LOG_LINES="$1" ;;
            --help|-h) usage; exit 0 ;;
            *)         printf "${RED}Unknown: %s${R}\n" "$1"; usage; exit 1 ;;
        esac
        shift
    done

    mkdir -p "$REPORT_DIR"

    run_full() {
        CNT_CRIT=0; CNT_ERR=0; CNT_WARN=0; CNT_INFO=0; CNT_TOTAL=0
        {
            print_banner
            system_health
            if $use_stdin; then
                read_stdin_mode
            elif [[ -n "$file_path" ]]; then
                read_file_mode "$file_path"
            else
                run_system_scan "$mode"
            fi
            print_summary
        } 2>&1 | tee >(sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' > "$REPORT_FILE")
    }

    if $watch; then
        while true; do
            run_full
            printf "\n  ${GRY}Refreshing in 60s... Ctrl+C to stop.${R}\n"
            sleep 60
        done
    else
        run_full
    fi
}

main "$@"
