#!/usr/bin/env bash
# ==============================================================================
#  LINUX ERR DOCTOR  v4.0
#  Fetches, parses, and explains Linux system log errors in plain English.
#
#  PRIMARY DATA SOURCES (exactly as requested):
#    journalctl -p err -b --no-pager       # all errors since last boot
#    systemctl --failed                     # all failed services
#    dmesg -T --level=err,crit             # kernel errors with timestamps
#    sudo smartctl -a /dev/sda             # disk SMART health
#
#  EXTENDED OS-WIDE COVERAGE (grep-based):
#    /var/log/syslog, /var/log/messages, /var/log/kern.log
#    /var/log/auth.log, /var/log/secure
#    /var/log/dpkg.log, /var/log/apt/history.log
#    /var/log/Xorg.0.log, /var/log/boot.log
#    /var/log/nginx/error.log, /var/log/apache2/error.log
#    /var/log/mysql/error.log, /var/log/postgresql/*.log
#    /var/log/docker.log, /var/log/cups/error_log
#    /var/log/mail.err, /var/log/fail2ban.log
#    journalctl per-unit deep-dive for every failed service
#
#  Usage:
#    sudo ./linux_error_doctor.sh              # full system scan
#    sudo ./linux_error_doctor.sh --quick      # journal + failed services only
#    cat /var/log/syslog | ./linux_error_doctor.sh --stdin
#    ./linux_error_doctor.sh --file mylog.txt
#    sudo ./linux_error_doctor.sh --watch      # continuous live monitoring
#    sudo ./linux_error_doctor.sh --smart /dev/nvme0
#    sudo ./linux_error_doctor.sh --interval 30 --watch
#    ./linux_error_doctor.sh --help
# ==============================================================================

set -uo pipefail
IFS=$'\n\t'

# ── Config ────────────────────────────────────────────────────────────────────
VERSION="4.0"
LOG_LINES=300
JOURNAL_HOURS=24
REPORT_DIR="${HOME}/.errordoctor/reports"
REPORT_FILE="${REPORT_DIR}/report_$(date +%Y%m%d_%H%M%S).txt"
SMART_DISK="${SMART_DISK:-/dev/sda}"
WATCH_INTERVAL=60

# ── Colors ────────────────────────────────────────────────────────────────────
R="\033[0m"
BOLD="\033[1m"; DIM="\033[2m"
RED="\033[38;5;196m";  ORA="\033[38;5;208m";  YEL="\033[38;5;226m"
GRN="\033[38;5;82m";   CYA="\033[38;5;51m";   BLU="\033[38;5;33m"
MAG="\033[38;5;201m";  WHT="\033[38;5;255m";  GRY="\033[38;5;245m"
DGR="\033[38;5;238m"
BG_CRIT="\033[48;5;196m"; BG_HDR="\033[48;5;17m"
BG_WARN="\033[48;5;58m";  BG_OK="\033[48;5;22m"

# ── Counters ──────────────────────────────────────────────────────────────────
CNT_CRIT=0; CNT_ERR=0; CNT_WARN=0; CNT_INFO=0; CNT_TOTAL=0
CNT_SMART_FAIL=0; CNT_SERVICES_FAILED=0

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

kv() { printf "  ${CYA}${BOLD}%-30s${R}  ${WHT}%s${R}\n" "$1" "$2"; }

cmd_ok() { command -v "$1" &>/dev/null; }

badge() {
    case "${1^^}" in
        CRITICAL) printf "${BG_CRIT}${WHT}${BOLD} CRITICAL ${R}" ;;
        ERROR)    printf "${RED}${BOLD}[  ERROR  ]${R}" ;;
        WARNING)  printf "${BG_WARN}${WHT}${BOLD}[ WARNING ]${R}" ;;
        INFO)     printf "${GRN}${BOLD}[  INFO   ]${R}" ;;
        OK)       printf "${BG_OK}${WHT}${BOLD}[   OK    ]${R}" ;;
        *)        printf "${GRY}${BOLD}[ UNKNOWN ]${R}" ;;
    esac
}

# ── Master error classifier ────────────────────────────────────────────────────
classify() {
    local l="${1,,}"
    [[ "$l" =~ (critical|emerg|panic|out.of.memory|oom.killer|soft.lockup|hard.lockup|bug:|gpu.hang|fallen.off.the.bus|gpu.lockup|nvme.*reset.controller|bios.error|gpu.reset.begin|kernel.oops|kernel.bug|double.fault|general.protection.fault|thermal.*critical|ecc.*ue|machine.check.exception|mce|nvrm.*xid.*79|disk.failure) ]] \
        && echo CRITICAL && return
    [[ "$l" =~ (error|failed|failure|segfault|buffer.i\/o|i\/o.error|xid.*79|nvme.*timeout|dhcp.*failed|unable.to.enumerate|apparmor.*denied|syn.flood|syn.flooding|connection.refused|connection.reset|authentication.fail|tls.error|ssl.error|certificate.error|ata.*error|sata.*error|scsi.*error|edac.*ce|reallocated.sector|pending.sector|uncorrectable) ]] \
        && echo ERROR && return
    [[ "$l" =~ (warn|timeout|timed.out|mounting.fs.with.errors|possible.syn|module.verification.failed|failed.to.load|opcode.*failed|activation.*failed|link.down|disconnect|overrun|overflow|thermal.*warn|temperature.high|wear.level|high.temperature|power.loss) ]] \
        && echo WARNING && return
    [[ "$l" =~ (info|notice|succeeded|resume) ]] \
        && echo INFO && return
    echo UNKNOWN
}

# ==============================================================================
#  EXPLAIN ENGINE — Pattern-match and explain every known Linux error
# ==============================================================================
explain_line() {
    local line="$1"
    local sev; sev=$(classify "$line")
    local ts cat explanation fix
    ts=$(echo "$line" | grep -oE "^[A-Za-z]+ +[0-9]+ +[0-9:]+" 2>/dev/null \
        || echo "$line" | grep -oE "\[[0-9]+\.[0-9]+\]" 2>/dev/null || echo "")
    cat="System"; explanation=""; fix=""

    # ── GPU: AMD amdgpu ───────────────────────────────────────────────────────
    if [[ "$line" =~ "amdgpu" ]]; then
        if   [[ "$line" =~ "ring gfx timeout" ]]; then
            cat="GPU - AMD GFX Ring Timeout"
            explanation="AMD GPU command queue timed out. GPU stopped executing graphics commands."
            fix="Check GPU temps (sensors); update amdgpu driver; reduce GPU load."
        elif [[ "$line" =~ "GPU reset begin" ]]; then
            cat="GPU - AMD Reset Initiated"
            explanation="Emergency AMD GPU reset to recover from the hang."
            fix="Frequent resets = hardware issue. Check thermal paste, PSU power, GPU seating."
        elif [[ "$line" =~ "GPU reset succeeded" ]]; then
            cat="GPU - AMD Reset Recovered"
            explanation="AMD GPU successfully recovered from a hang via hardware reset."
            fix="Monitor for recurrence. If frequent, check GPU cooling and driver version."
        elif [[ "$line" =~ "GPU reset failed" ]]; then
            cat="GPU - AMD Reset FAILED (CRITICAL)"
            explanation="AMD GPU could NOT recover from the hang. System may be unstable."
            fix="Reboot. If recurring: reseat GPU, check PCIe slot, test PSU rails."
        elif [[ "$line" =~ "error" ]]; then
            cat="GPU - AMD Error"
            explanation="AMD GPU driver reported an error."
            fix="journalctl -k --grep=amdgpu | tail -50  |  update mesa/amdgpu driver"
        fi
    fi

    # ── GPU: Intel i915 ───────────────────────────────────────────────────────
    if [[ "$line" =~ "i915" ]]; then
        if   [[ "$line" =~ "GPU HANG" ]]; then
            cat="GPU - Intel GPU Hang"
            explanation="Intel integrated GPU (i915) crashed hard. GPU stopped processing commands."
            fix="sudo apt install intel-microcode linux-firmware && sudo reboot"
        elif [[ "$line" =~ "Resetting chip" ]]; then
            cat="GPU - Intel GPU Reset"
            explanation="Intel GPU heartbeat stopped. Kernel is resetting the GPU chip."
            fix="Update linux-firmware: sudo apt install --reinstall linux-firmware"
        elif [[ "$line" =~ "error" ]]; then
            cat="GPU - Intel i915 Error"
            explanation="Intel i915 GPU driver reported an error."
            fix="dmesg | grep i915  |  sudo apt install --reinstall linux-firmware"
        fi
    fi

    # ── GPU: Nouveau (open Nvidia) ─────────────────────────────────────────────
    if [[ "$line" =~ "nouveau" ]]; then
        if [[ "$line" =~ "GPU lockup" ]]; then
            cat="GPU - Nouveau Lockup (Fallback Mode)"
            explanation="Open-source Nvidia driver (nouveau) detected a GPU lockup."
            fix="Install proprietary: sudo ubuntu-drivers autoinstall  OR  sudo apt install nvidia-driver-535"
        elif [[ "$line" =~ "error" || "$line" =~ "failed" ]]; then
            cat="GPU - Nouveau Driver Error"
            explanation="Nouveau (open-source Nvidia) driver error."
            fix="Switch to proprietary Nvidia driver: sudo ubuntu-drivers autoinstall"
        fi
    fi

    # ── GPU: Nvidia proprietary ───────────────────────────────────────────────
    if [[ "$line" =~ "NVRM" ]]; then
        if [[ "$line" =~ "GPU has fallen off the bus" ]]; then
            cat="GPU - Nvidia BUS FAILURE (CRITICAL)"
            explanation="Nvidia GPU completely disappeared from PCIe bus. Catastrophic hardware failure."
            fix="1. Reseat GPU  2. Check power connectors  3. Test PSU  4. GPU may be dead"
        elif [[ "$line" =~ "Xid" ]]; then
            local xid; xid=$(echo "$line" | grep -oE "Xid [0-9]+" | awk '{print $2}')
            cat="GPU - Nvidia XID Error ($xid)"
            case "$xid" in
                79) explanation="GPU fallen off PCIe bus (XID 79). Hardware failure."
                    fix="Reseat GPU, check power cables, test with another PCIe slot." ;;
                13) explanation="Graphics engine exception (XID 13). Driver or hardware bug."
                    fix="Update Nvidia driver: sudo apt install --reinstall nvidia-driver-*" ;;
                31) explanation="GPU memory corruption (XID 31). ECC error or bad VRAM."
                    fix="Run: nvidia-smi -q -d ECC  |  Replace GPU if persistent." ;;
                43) explanation="GPU video engine exception (XID 43)."
                    fix="Update driver; check GPU cooling." ;;
                *)  explanation="Nvidia XID error code $xid. GPU fault."
                    fix="Check nvidia-smi; update Nvidia drivers." ;;
            esac
        fi
    fi
    if [[ "$line" =~ "nvidia" && "$line" =~ "module verification failed" ]]; then
        cat="GPU - Nvidia Secure Boot Conflict"
        explanation="Nvidia kernel module signature verification failed. Secure Boot blocking driver."
        fix="sudo mokutil --import /var/lib/shim-signed/mok/MOK.der && reboot  OR  Disable Secure Boot in BIOS"
    fi

    # ── MCE: Machine Check Exception ──────────────────────────────────────────
    if [[ "$line" =~ [Mm][Cc][Ee] || "$line" =~ "Machine check" || "$line" =~ "hardware error" ]]; then
        cat="CPU/Hardware - Machine Check Exception (CRITICAL)"
        explanation="CPU hardware error detected by MCE monitors. Could be CPU, RAM, or motherboard fault."
        fix="sudo mcelog --client  |  Check RAM: sudo memtest86+  |  Check CPU temps and PSU"
    fi

    # ── CPU: Soft/Hard Lockup ──────────────────────────────────────────────────
    if [[ "$line" =~ "soft lockup" ]]; then
        cat="CPU - Soft Lockup (CRITICAL)"
        explanation="CPU core stuck >20s without releasing scheduler. Kernel deadlock or interrupt storm."
        fix="ps aux --sort=-%cpu | head  |  cat /proc/interrupts  |  Check for runaway process"
    fi
    if [[ "$line" =~ "hard LOCKUP" || "$line" =~ "NMI watchdog" ]]; then
        cat="CPU - Hard Lockup (CRITICAL)"
        explanation="CPU completely stopped — NMI watchdog triggered. System was fully frozen."
        fix="Check CPU temps; echo 0 > /sys/devices/system/cpu/cpufreq/boost to disable turbo"
    fi
    if [[ "$line" =~ "hung_task" || "$line" =~ "blocked for more than" ]]; then
        cat="CPU - Hung Task Detected"
        explanation="A kernel task has been blocked in D-state (uninterruptible sleep) >120s. Usually blocked I/O."
        fix="dmesg | grep -i 'i/o error'  |  Likely disk failure — run smartctl -a /dev/sda"
    fi

    # ── Memory: OOM Killer ────────────────────────────────────────────────────
    if [[ "$line" =~ "Out of memory" && "$line" =~ "Killed process" ]]; then
        local proc; proc=$(echo "$line" | grep -oE "\([a-z]+\)" | tr -d '()' | head -1)
        cat="Memory - OOM Killer (CRITICAL)"
        explanation="System ran out of RAM. Kernel OOM killer terminated process '$proc' to free memory."
        fix="sudo fallocate -l 4G /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile  |  Add more RAM"
    fi
    if [[ "$line" =~ "oom-kill" || "$line" =~ "oom_reaper" ]]; then
        cat="Memory - OOM Kill Event"
        explanation="OOM kill event: a process was forcibly killed to recover memory."
        fix="free -h  |  ps aux --sort=-%mem | head -15"
    fi

    # ── Memory: ECC Errors ────────────────────────────────────────────────────
    if [[ "$line" =~ "EDAC" ]]; then
        if   [[ "$line" =~ " CE " ]]; then
            cat="Memory - ECC Correctable Error (CE)"
            explanation="ECC RAM corrected a single-bit memory error. RAM may be degrading."
            fix="edac-util -s 0  |  Replace DIMM if errors keep increasing."
        elif [[ "$line" =~ " UE " ]]; then
            cat="Memory - ECC Uncorrectable Error UE (CRITICAL)"
            explanation="ECC RAM detected an UNCORRECTABLE multi-bit error. Data corruption occurred."
            fix="CRITICAL: Replace affected RAM DIMM immediately. Run memtest86+ to identify bad module."
        fi
    fi

    # ── Storage: I/O Errors ───────────────────────────────────────────────────
    if [[ "$line" =~ "Buffer I/O error" ]]; then
        cat="Storage - Buffer I/O Error (Disk Failing)"
        explanation="Kernel failed to read/write disk block. Drive has bad sectors or is failing."
        fix="sudo smartctl -a /dev/sda  |  Back up data immediately  |  Replace drive if SMART fails"
    fi
    if [[ "$line" =~ "I/O error" && "$line" =~ "sector" ]]; then
        cat="Storage - Bad Sector Detected"
        explanation="A specific disk sector is unreadable. Physical bad sector — drive is likely failing."
        fix="sudo smartctl -a /dev/sda  |  IMMEDIATE: Back up all data and replace drive"
    fi
    if [[ "$line" =~ "ata" && ( "$line" =~ "error" || "$line" =~ "failed" ) ]]; then
        local ata_err; ata_err=$(echo "$line" | grep -oE "(DRDY|ERR|ICRC|ABRT|UNC|IDNF|MC|MCR|NM|ILI)" | tr '\n' ',' | sed 's/,$//')
        cat="Storage - ATA/SATA Error (${ata_err:-check log})"
        explanation="ATA/SATA drive error: ${ata_err}. DRDY=Not Ready, UNC=Uncorrectable, ABRT=Aborted, ICRC=CRC fail."
        fix="sudo smartctl -a /dev/sda  |  Check cable/power  |  Back up immediately"
    fi
    if [[ "$line" =~ "SCSI" && "$line" =~ "error" ]]; then
        cat="Storage - SCSI Error"
        explanation="SCSI/SAS device reported an error. May indicate controller or drive failure."
        fix="sudo smartctl -a /dev/sda  |  Check SCSI host adapter"
    fi

    # ── Storage: NVMe ─────────────────────────────────────────────────────────
    if [[ "$line" =~ "nvme" ]]; then
        if   [[ "$line" =~ "timeout" && "$line" =~ "aborting" ]]; then
            cat="Storage - NVMe I/O Timeout"
            explanation="NVMe SSD command timed out and was aborted. SSD became unresponsive."
            fix="sudo nvme smart-log /dev/nvme0 | grep temperature  |  Update NVMe firmware"
        elif [[ "$line" =~ "reset controller" ]]; then
            cat="Storage - NVMe Controller Reset (CRITICAL)"
            explanation="NVMe SSD controller stopped responding. Kernel forced hardware reset. Risk of data loss."
            fix="Check NVMe temps  |  nvme fw-download  |  Replace SSD if resets continue"
        elif [[ "$line" =~ "write error" || "$line" =~ "failed to write" ]]; then
            cat="Storage - NVMe Write Error"
            explanation="NVMe failed to complete a write. Drive may be failing or out of write endurance."
            fix="sudo nvme smart-log /dev/nvme0 | grep -E 'percentage_used|media_errors'"
        fi
    fi

    # ── Filesystem: EXT4 ──────────────────────────────────────────────────────
    if [[ "$line" =~ "EXT4-fs error" ]]; then
        cat="Filesystem - EXT4 Corruption (CRITICAL)"
        explanation="EXT4 filesystem corruption detected. A directory entry could not be read — filesystem is damaged."
        fix="URGENT: Back up NOW! sudo fsck -f /dev/sda2 (boot from live USB first)"
    elif [[ "$line" =~ "EXT4-fs warning" && "$line" =~ "mounting fs with errors" ]]; then
        cat="Filesystem - EXT4 Mounted With Errors"
        explanation="EXT4 filesystem mounted despite known errors. Data integrity at risk."
        fix="sudo touch /forcefsck && reboot  OR  boot live USB and run fsck"
    fi
    if [[ "$line" =~ "XFS" && "$line" =~ "error" ]]; then
        cat="Filesystem - XFS Error (CRITICAL)"
        explanation="XFS filesystem reported an error. May indicate corruption or I/O failure."
        fix="sudo xfs_repair /dev/sdX (unmount first)  |  Back up data immediately"
    fi
    if [[ "$line" =~ "BTRFS" && ( "$line" =~ "error" || "$line" =~ "corruption" ) ]]; then
        cat="Filesystem - BTRFS Error"
        explanation="BTRFS filesystem error or corruption detected."
        fix="sudo btrfs check /dev/sdX  |  sudo btrfs scrub start /mount/point"
    fi
    if [[ "$line" =~ "Failed to mount" && "$line" =~ "systemd" ]]; then
        cat="Filesystem - Mount Failed"
        explanation="systemd could not mount a filesystem. Device may be missing, wrong fs type, or has errors."
        fix="Check /etc/fstab; lsblk; sudo mount -a && journalctl -u mnt-data.mount"
    fi

    # ── Network: NetworkManager ────────────────────────────────────────────────
    if [[ "$line" =~ "NetworkManager" ]]; then
        if   [[ "$line" =~ "Failed to start" ]]; then
            cat="Network - NetworkManager Service Failed"
            explanation="NetworkManager failed to start. No network management active."
            fix="sudo systemctl restart NetworkManager && journalctl -u NetworkManager -n 50"
        elif [[ "$line" =~ "Dependency failed" ]]; then
            cat="Network - Dependency Chain Failed"
            explanation="A dependency of NetworkManager failed first."
            fix="systemctl status NetworkManager  |  systemctl --failed"
        fi
    fi

    # ── Network: DHCP ─────────────────────────────────────────────────────────
    if [[ "$line" =~ "dhcp" || "$line" =~ "dhclient" ]]; then
        if [[ "$line" =~ "timed out" || "$line" =~ "No DHCPOFFERS" ]]; then
            cat="Network - DHCP Timeout"
            explanation="DHCP request got no response from router. No IP address assigned."
            fix="sudo dhclient -r && sudo dhclient eth0  |  sudo systemctl restart NetworkManager"
        elif [[ "$line" =~ "config -> failed" ]]; then
            cat="Network - DHCP State Machine Failed"
            explanation="DHCP state machine failed. Interface has no IP — no internet."
            fix="sudo systemctl restart NetworkManager  OR  nmcli device disconnect wlan0 && nmcli device connect wlan0"
        fi
    fi

    # ── Network: Link Down ─────────────────────────────────────────────────────
    if [[ "$line" =~ "link is not ready" || "$line" =~ "Link is Down" || "$line" =~ "carrier lost" ]]; then
        local iface; iface=$(echo "$line" | grep -oE "[a-z]+[0-9]+" | head -1 || echo "interface")
        cat="Network - Link Down ($iface)"
        explanation="Network interface $iface lost carrier/link. Cable disconnected or switch issue."
        fix="ip link show $iface  |  sudo ethtool $iface  |  Check cable"
    fi

    # ── Network: SYN Flood ────────────────────────────────────────────────────
    if [[ "$line" =~ "SYN flood" || "$line" =~ "SYN flooding" || "$line" =~ "possible SYN flooding" ]]; then
        cat="Network - SYN Flood Attack Detected"
        explanation="Kernel detected high TCP SYN requests on a port. Classic DDoS pattern."
        fix="sudo ufw limit 443/tcp  |  sudo apt install fail2ban  |  Use Cloudflare DDoS protection"
    fi

    # ── Network: Connection Refused / Reset ───────────────────────────────────
    if [[ "$line" =~ "Connection refused" || "$line" =~ "connection refused" ]]; then
        cat="Network - Connection Refused"
        explanation="A service actively refused a connection. The service may be down or not listening."
        fix="Check if service is running: systemctl status <service>  |  netstat -tlnp"
    fi
    if [[ "$line" =~ "Network is unreachable" ]]; then
        cat="Network - Network Unreachable"
        explanation="No route to network. Routing table missing or network interface down."
        fix="ip route show  |  sudo ip route add default via GATEWAY_IP  |  sudo systemctl restart NetworkManager"
    fi

    # ── Network: CIFS / Samba ─────────────────────────────────────────────────
    if [[ "$line" =~ "CIFS" && "$line" =~ "send error" ]]; then
        cat="Network - CIFS/Samba Mount Error"
        explanation="Failed to connect/authenticate to Windows/Samba network share."
        fix="sudo mount -t cifs //server/share /mnt -o user=X,pass=Y,vers=3.0"
    fi

    # ── Security: TLS/SSL/Certificate ────────────────────────────────────────
    if [[ "$line" =~ "SSL" || "$line" =~ "TLS" || "$line" =~ "certificate" ]]; then
        if [[ "$line" =~ "error" || "$line" =~ "fail" || "$line" =~ "expire" ]]; then
            cat="Security - TLS/SSL Certificate Error"
            explanation="TLS/SSL certificate error or expiry. Secure connections may be failing."
            fix="openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -dates"
        fi
    fi

    # ── Security: SSH Brute Force ─────────────────────────────────────────────
    if [[ "$line" =~ "Failed password" && "$line" =~ "sshd" ]]; then
        local ip; ip=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
        local uname; uname=$(echo "$line" | grep -oE "for (invalid user )?[^ ]+ from" | sed 's/ from//' | awk '{print $NF}')
        cat="Security - SSH Brute Force from ${ip}"
        explanation="Failed SSH login from $ip attempting user '$uname'. Unauthorized access attempt."
        fix="sudo ufw deny from $ip  |  sudo apt install fail2ban  |  Set PasswordAuthentication no in /etc/ssh/sshd_config"
    fi
    if [[ "$line" =~ "Invalid user" && "$line" =~ "sshd" ]]; then
        local baduser; baduser=$(echo "$line" | awk '{print $3}')
        local badip; badip=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | tail -1)
        cat="Security - SSH Invalid User from $badip"
        explanation="SSH login with non-existent user '$baduser' from $badip."
        fix="sudo ufw deny from $badip  |  sudo apt install fail2ban"
    fi
    if [[ "$line" =~ "POSSIBLE BREAK-IN ATTEMPT" ]]; then
        cat="Security - POSSIBLE BREAK-IN ATTEMPT (CRITICAL)"
        explanation="SSH reverse DNS mismatch detected — possible IP spoofing or break-in."
        fix="sudo journalctl -u sshd | grep -i break  |  sudo ufw status"
    fi

    # ── Security: PAM / Auth ──────────────────────────────────────────────────
    if [[ "$line" =~ "pam_unix" && "$line" =~ "authentication failure" ]]; then
        cat="Auth - Login Failed (PAM)"
        explanation="Login attempt failed — wrong password. PAM authentication rejected."
        fix="If not you: sudo lastb | head -20  |  Check for unauthorized local access"
    fi
    if [[ "$line" =~ "sudo" && "$line" =~ "authentication failure" ]]; then
        cat="Security - Sudo Auth Failure"
        explanation="Someone tried to use sudo but failed authentication."
        fix="sudo last -F | grep -i fail  |  getent group sudo"
    fi

    # ── Security: AppArmor / SELinux ──────────────────────────────────────────
    if [[ "$line" =~ "apparmor" && "${line,,}" =~ "denied" ]]; then
        local op; op=$(echo "$line" | grep -oE 'operation="[^"]*"' | cut -d'"' -f2 || echo "unknown")
        cat="Security - AppArmor Access Denied"
        explanation="AppArmor DENIED operation '$op'. A process tried something not allowed by its security profile."
        fix="sudo aa-complain <profile>  |  sudo journalctl -k --grep=apparmor"
    fi
    if [[ "$line" =~ "SELinux" && "${line,,}" =~ "denied" ]]; then
        cat="Security - SELinux Access Denied"
        explanation="SELinux security module denied an operation."
        fix="audit2why < /var/log/audit/audit.log  |  audit2allow -a -M mymodule"
    fi

    # ── ACPI / BIOS ───────────────────────────────────────────────────────────
    if [[ "$line" =~ "ACPI BIOS Error" ]]; then
        cat="ACPI - BIOS Firmware Bug"
        explanation="BIOS/UEFI ACPI table has a bug. Kernel found an error parsing hardware config."
        fix="Update BIOS/UEFI to latest version from motherboard manufacturer's website."
    elif [[ "$line" =~ "ACPI Error" && "$line" =~ "AE_NOT_FOUND" ]]; then
        cat="ACPI - Named Object Not Found"
        explanation="ACPI firmware references a hardware object that doesn't exist — firmware inconsistency."
        fix="Usually benign. If features fail (fans, power states): update BIOS firmware."
    fi

    # ── Thermal / Temperature ──────────────────────────────────────────────────
    if [[ "$line" =~ "thermal" || "$line" =~ "ACPI: Thermal" ]]; then
        if   [[ "$line" =~ "critical" || "$line" =~ "shutdown" ]]; then
            cat="Thermal - Critical Temperature (CRITICAL)"
            explanation="System reached critical thermal threshold. Emergency shutdown initiated."
            fix="Check CPU/GPU cooling immediately. Clean dust. Check thermal paste. Improve airflow."
        elif [[ "$line" =~ "trip" || "$line" =~ "throttl" ]]; then
            cat="Thermal - CPU Throttling (Overheating)"
            explanation="CPU overheating and throttling to cool down."
            fix="sensors | grep -i temp  |  Clean fans/heatsink  |  Reapply thermal paste"
        fi
    fi

    # ── Bluetooth ─────────────────────────────────────────────────────────────
    if [[ "$line" =~ "Bluetooth" && "$line" =~ "failed" && "$line" =~ "Opcode" ]]; then
        cat="Bluetooth - HCI Command Timeout"
        explanation="Bluetooth HCI command failed (-110 ETIMEDOUT). Controller stopped responding."
        fix="sudo systemctl restart bluetooth  |  sudo rmmod btusb && sudo modprobe btusb"
    fi

    # ── WiFi: Intel iwlwifi ───────────────────────────────────────────────────
    if [[ "$line" =~ "iwlwifi" ]]; then
        if   [[ "$line" =~ "failed to load" ]]; then
            local fw; fw=$(echo "$line" | grep -oE "iwlwifi[^ ]*\.ucode" || echo "firmware")
            cat="WiFi - Intel Firmware Missing"
            explanation="Intel WiFi driver cannot find firmware file '$fw'. WiFi will not function."
            fix="sudo apt install linux-firmware && sudo update-initramfs -u && sudo reboot"
        elif [[ "$line" =~ "Failed to start RT ucode" ]]; then
            cat="WiFi - Intel WiFi RT Firmware Failed"
            explanation="Intel WiFi real-time firmware load timed out. WiFi completely non-functional."
            fix="sudo apt install --reinstall linux-firmware && reboot"
        elif [[ "$line" =~ "microcode SW error" || "$line" =~ "FW error" ]]; then
            cat="WiFi - Intel WiFi Firmware Error"
            explanation="Intel WiFi firmware crashed or reported a software error."
            fix="sudo apt install --reinstall linux-firmware && reboot  |  sudo modprobe -r iwlwifi && sudo modprobe iwlwifi"
        fi
    fi
    if [[ "$line" =~ "ath" && ( "$line" =~ "error" || "$line" =~ "failed" ) ]]; then
        cat="WiFi - Atheros Driver Error"
        explanation="Atheros WiFi driver (ath9k/ath10k) reported an error."
        fix="sudo apt install --reinstall linux-firmware  |  sudo modprobe -r ath10k_pci && sudo modprobe ath10k_pci"
    fi

    # ── USB ───────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "usb" ]]; then
        if   [[ "$line" =~ "device descriptor read" && "$line" =~ "error -71" ]]; then
            cat="USB - Protocol Error (-71 EPROTO)"
            explanation="USB device failed with error -71 (protocol error). Bad cable or faulty device."
            fix="Try different USB cable and port. Error -71 is almost always a cable quality issue."
        elif [[ "$line" =~ "unable to enumerate" ]]; then
            cat="USB - Enumeration Failed"
            explanation="Kernel cannot identify/initialize the USB device. Device invisible to OS."
            fix="Try different USB port and cable. Test on another machine. May be hardware failure."
        elif [[ "$line" =~ "power budget exceeded" ]]; then
            cat="USB - Power Budget Exceeded"
            explanation="USB device requires more power than the port can supply."
            fix="Use a powered USB hub. Avoid high-power devices on USB 2.0 ports."
        elif [[ "$line" =~ "reset" && "$line" =~ "error" ]]; then
            cat="USB - Reset Error"
            explanation="USB device required a reset but failed to recover."
            fix="Unplug and re-plug device. Try another USB port."
        fi
    fi

    # ── PCIe Bus Error ────────────────────────────────────────────────────────
    if [[ "$line" =~ "PCIe Bus Error" ]]; then
        local pcie_sev; pcie_sev=$(echo "$line" | grep -oE "severity=[A-Za-z]+" | cut -d= -f2)
        cat="Hardware - PCIe Bus Error (${pcie_sev:-unknown})"
        explanation="PCIe bus hardware error (severity: ${pcie_sev:-unknown}). Seen with GPUs, NVMe, or NICs."
        fix="'Corrected' = monitor only. 'Uncorrected/Fatal' = reseat PCIe card; check slot; update BIOS"
    fi

    # ── Docker ────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "docker" ]]; then
        if   [[ "$line" =~ "FAILURE" && "$line" =~ "Main process exited" ]]; then
            cat="Docker - Daemon Crashed"
            explanation="Docker daemon exited with FAILURE. All containers are now stopped."
            fix="sudo systemctl stop docker && sudo ip link delete docker0 2>/dev/null; sudo systemctl start docker"
        elif [[ "$line" =~ "failed to start daemon" ]]; then
            cat="Docker - Network Controller Failed"
            explanation="Docker cannot initialize network controller. Leftover bridge conflict."
            fix="sudo ip link delete docker0; sudo iptables -t nat -F; sudo systemctl restart docker"
        elif [[ "$line" =~ "Failed to start docker.service" ]]; then
            cat="Docker - Service Startup Failed"
            explanation="systemd could not start docker.service."
            fix="journalctl -u docker -n 50  |  sudo systemctl restart docker"
        fi
    fi

    # ── Snap ──────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "snapd" && ( "$line" =~ "error" || "$line" =~ "failed" ) ]]; then
        cat="Package - Snapd Error"
        explanation="Snap daemon (snapd) reported an error. Snap packages may not work."
        fix="sudo systemctl restart snapd  |  sudo snap refresh  |  journalctl -u snapd -n 30"
    fi

    # ── APT / dpkg ────────────────────────────────────────────────────────────
    if [[ "$line" =~ "dpkg" || "$line" =~ "apt" ]] && [[ "$line" =~ "error" || "$line" =~ "failed" ]]; then
        cat="Package - APT/DPKG Error"
        explanation="Package manager (apt/dpkg) encountered an error during install or configuration."
        fix="sudo dpkg --configure -a  |  sudo apt-get install -f  |  sudo apt clean && sudo apt update"
    fi

    # ── Systemd unit failures ─────────────────────────────────────────────────
    if [[ "$line" =~ "user@" && "$line" =~ "code=killed" && "$line" =~ "status=9/KILL" ]]; then
        cat="Session - User Session Killed by OOM"
        explanation="User session killed by SIGKILL (OOM killer). Desktop session likely crashed."
        fix="Add swap or RAM. Identify hogs: ps aux --sort=-%mem | head -10"
    fi
    if [[ "$line" =~ "Failed to start" && "$line" =~ "systemd" && -z "$explanation" ]]; then
        local svc; svc=$(echo "$line" | grep -oE "[a-zA-Z0-9_.-]+\.service" | head -1 || echo "service")
        cat="Service - Systemd Unit Failed"
        explanation="systemd could not start '$svc'. The service is down."
        fix="journalctl -u $svc -n 30  |  sudo systemctl restart $svc"
    fi

    # ── D-Bus ─────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "dbus" && "$line" =~ "timed out" ]]; then
        cat="D-Bus - Service Activation Timeout"
        explanation="D-Bus tried to start a service but it did not respond in time."
        fix="journalctl -p err | grep dbus  |  systemctl status <service>"
    fi

    # ── Kernel BUG / Oops ─────────────────────────────────────────────────────
    if [[ "$line" =~ "kernel BUG" || "$line" =~ "Oops:" || "$line" =~ "general protection fault" || "$line" =~ "double fault" ]]; then
        cat="Kernel - BUG/Oops (CRITICAL)"
        explanation="Kernel detected an internal bug or unexpected fault. System may be unstable."
        fix="Note RIP/stack trace and report to kernel.org or distro. Reboot required."
    fi

    # ── Web Servers ───────────────────────────────────────────────────────────
    if [[ "$line" =~ "nginx" && ( "$line" =~ "error" || "$line" =~ "crit" || "$line" =~ "emerg" ) ]]; then
        cat="Web Server - Nginx Error"
        explanation="Nginx web server reported an error."
        fix="sudo nginx -t  |  sudo systemctl restart nginx  |  tail -f /var/log/nginx/error.log"
    fi
    if [[ ( "$line" =~ "apache" || "$line" =~ "httpd" ) && ( "$line" =~ "error" || "$line" =~ "crit" ) ]]; then
        cat="Web Server - Apache Error"
        explanation="Apache web server reported an error."
        fix="sudo apachectl configtest  |  sudo systemctl restart apache2  |  tail -f /var/log/apache2/error.log"
    fi

    # ── Databases ─────────────────────────────────────────────────────────────
    if [[ ( "$line" =~ "mysql" || "$line" =~ "mysqld" ) && ( "$line" =~ "error" || "$line" =~ "fail" ) ]]; then
        cat="Database - MySQL Error"
        explanation="MySQL database server reported an error."
        fix="sudo systemctl restart mysql  |  journalctl -u mysql -n 50"
    fi
    if [[ ( "$line" =~ "postgres" || "$line" =~ "postgresql" ) && ( "$line" =~ "error" || "$line" =~ "FATAL" || "$line" =~ "PANIC" ) ]]; then
        cat="Database - PostgreSQL Error"
        explanation="PostgreSQL database server reported an error or fatal condition."
        fix="sudo systemctl restart postgresql  |  journalctl -u postgresql -n 50"
    fi

    # ── Cron ──────────────────────────────────────────────────────────────────
    if [[ "$line" =~ "CRON" && ( "$line" =~ "error" || "$line" =~ "failed" ) ]]; then
        cat="Scheduler - Cron Job Error"
        explanation="A scheduled cron job encountered an error."
        fix="Check /var/log/syslog for cron output  |  sudo crontab -l  |  journalctl -u cron"
    fi

    # ── CUPS / Printing ───────────────────────────────────────────────────────
    if [[ "$line" =~ "cups" && ( "$line" =~ "error" || "$line" =~ "failed" ) ]]; then
        cat="Printing - CUPS Error"
        explanation="CUPS print server reported an error."
        fix="sudo systemctl restart cups  |  lpstat -t  |  journalctl -u cups -n 20"
    fi

    # ── Xorg / Display ────────────────────────────────────────────────────────
    if [[ "$line" =~ "Xorg" || "$line" =~ "xf86" ]]; then
        if [[ "$line" =~ "(EE)" || "$line" =~ "error" ]]; then
            cat="Display - Xorg Error"
            explanation="Xorg display server reported an error. Desktop environment may be affected."
            fix="/var/log/Xorg.0.log | grep '(EE)'  |  sudo apt install --reinstall xorg"
        fi
    fi

    # ── fail2ban ──────────────────────────────────────────────────────────────
    if [[ "$line" =~ "fail2ban" ]]; then
        if [[ "$line" =~ "Ban" ]]; then
            local ban_ip; ban_ip=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            cat="Security - fail2ban Banned IP: $ban_ip"
            explanation="fail2ban banned IP $ban_ip for repeated failed attempts."
            fix="sudo fail2ban-client status sshd  |  sudo fail2ban-client unban $ban_ip"
        elif [[ "$line" =~ "error" || "$line" =~ "failed" ]]; then
            cat="Security - fail2ban Error"
            explanation="fail2ban reported an error."
            fix="sudo systemctl restart fail2ban  |  journalctl -u fail2ban -n 30"
        fi
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
#  ANALYZE A BATCH OF LOG LINES — master grep filter for entire OS
# ==============================================================================
analyze_lines() {
    local source_label="$1"; shift
    local lines_arr=("$@")
    local found=0

    box_header "SOURCE: ${source_label}" "$MAG"

    for line in "${lines_arr[@]+"${lines_arr[@]}"}"; do
        [[ -z "$line" ]] && continue
        # Master grep: captures all error-class patterns across the entire Linux OS
        if ! echo "${line,,}" | grep -qE \
            "(error|fail(ed|ure|ing)?|warn(ing)?|critical|emerg|alert|panic|oom|out.of.memory|killed.process|oom.killer|segfault|segmentation.fault|timeout|timed.out|lockup|soft.lockup|hard.lockup|bug:|kernel.bug|oops|hang(ing|ed)?|hung.task|i\/o.error|buffer.i\/o|bad.sector|read.error|write.error|corrupt(ed|ion)?|fallen.off.the.bus|gpu.hang|gpu.lockup|gpu.reset|nvme.*reset|nvme.*timeout|abort(ed)?|denied|refused|blocked|unable.to|cannot|could.not|missing|not.found|invalid|illegal|malformed|overrun|overflow|disconnect(ed)?|link.down|authentication.fail|auth.fail|access.denied|syn.flood|brute.force|certificate.error|ssl.error|tls.error|firmware.*fail|mount.*fail|fsck|connection.refused|connection.reset|network.unreachable|ata.*error|sata.*error|scsi.*error|memory.*error|ecc.error|thermal|overheat|acpi.*error|bios.*error|pcie.*error|pci.*error|xid|mce|edac|reallocated|uncorrectable|pending.sector|power.loss|wear.level|media.error|break-in|intrusion|banned|fail2ban)"; then
            continue
        fi
        found=1
        local parsed
        parsed=$(explain_line "$line")
        IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
        display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
    done

    [[ $found -eq 0 ]] && printf "\n  ${GRN}✔  No errors found in this source.${R}\n"
}

# ==============================================================================
#  SMART DISK HEALTH  ← sudo smartctl -a /dev/sda
# ==============================================================================
run_smart_check() {
    local disk="${1:-$SMART_DISK}"
    box_header "sudo smartctl -a $disk  [ DISK SMART HEALTH ]" "$YEL"

    if ! cmd_ok smartctl; then
        printf "\n  ${YEL}smartctl not found. Install: sudo apt install smartmontools${R}\n"
        return
    fi
    if [[ ${EUID:-1} -ne 0 ]]; then
        printf "\n  ${YEL}Root required for SMART. Run with sudo.${R}\n"
        return
    fi
    if [[ ! -b "$disk" ]]; then
        printf "\n  ${YEL}Block device %s not found. Use --smart /dev/nvme0 to specify disk.${R}\n" "$disk"
        return
    fi

    local smart_out
    smart_out=$(smartctl -a "$disk" 2>&1) || true

    echo ""
    # Overall health
    local health; health=$(echo "$smart_out" | grep -iE "SMART overall-health" | awk '{print $NF}')
    if [[ "${health^^}" == "PASSED" ]]; then
        badge "OK"; printf "  ${GRN}${BOLD} SMART Health: PASSED${R}\n"
    elif [[ -n "$health" ]]; then
        badge "CRITICAL"; printf "  ${RED}${BOLD} SMART Health: ${health} — DISK FAILURE IMMINENT!${R}\n"
        ((CNT_SMART_FAIL++))
        printf "  ${GRN}Fix:${R} ${GRN}Back up ALL data immediately and replace this disk!${R}\n"
    else
        printf "  ${GRY}SMART health: unknown (may need -d ata or -d nvme flag)${R}\n"
    fi

    echo ""
    printf "  ${CYA}${BOLD}Key SMART Attributes:${R}\n"

    # Critical HDD/SSD SMART attributes
    local -A attr_labels=(
        ["Reallocated_Sector_Ct"]="Reallocated Sectors (non-zero = bad)"
        ["Current_Pending_Sector"]="Pending Bad Sectors (non-zero = bad)"
        ["Offline_Uncorrectable"]="Offline Uncorrectable (non-zero = bad)"
        ["Reported_Uncorrect"]="Reported Uncorrectable (non-zero = bad)"
        ["Spin_Retry_Count"]="Spin Retry Count (HDD)"
        ["Command_Timeout"]="Command Timeout Count"
        ["End-to-End_Error"]="End-to-End Error Count"
        ["Power_On_Hours"]="Power-On Hours"
        ["Wear_Leveling_Count"]="Wear Leveling Count (SSD)"
        ["Media_Wearout_Indicator"]="Media Wearout Indicator (SSD)"
        ["SSD_Life_Left"]="SSD Life Left (%)"
    )

    for attr in "${!attr_labels[@]}"; do
        local val; val=$(echo "$smart_out" | grep -i "$attr" | awk '{print $NF}' | head -1)
        [[ -z "$val" ]] && continue
        local acolor="$GRN"
        # Flag non-zero values as bad for failure indicators
        case "$attr" in
            Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|Reported_Uncorrect|Spin_Retry_Count|Command_Timeout|End-to-End_Error)
                [[ "$val" =~ ^[0-9]+$ && "$val" -gt 0 ]] && { acolor="$RED"; ((CNT_SMART_FAIL++)); } ;;
        esac
        printf "  ${acolor}${BOLD}  %-40s${R}  ${WHT}%s${R}\n" "${attr_labels[$attr]}" "$val"
    done

    # Temperature
    local temp; temp=$(echo "$smart_out" | grep -iE "Temperature_Celsius" | awk '{print $NF}' | head -1)
    [[ -z "$temp" ]] && temp=$(echo "$smart_out" | grep -i "temperature" | grep -v "#" | awk '{print $NF}' | head -1)
    if [[ -n "$temp" && "$temp" =~ ^[0-9]+$ ]]; then
        local tc="$GRN"
        [[ "$temp" -gt 55 ]] && tc="$YEL"
        [[ "$temp" -gt 65 ]] && tc="$RED"
        printf "  ${tc}${BOLD}  %-40s${R}  ${WHT}%s°C${R}\n" "Drive Temperature" "$temp"
    fi

    # SMART error log count
    local err_count; err_count=$(echo "$smart_out" | grep -iE "error count|errors logged" | awk '{print $NF}' | head -1)
    if [[ -n "$err_count" && "$err_count" =~ ^[0-9]+$ && "$err_count" -gt 0 ]]; then
        printf "\n  ${RED}${BOLD}SMART Error Log: %s errors recorded on %s${R}\n" "$err_count" "$disk"
        ((CNT_SMART_FAIL++))
    fi

    # NVMe-specific fields
    if echo "$smart_out" | grep -q "NVMe Log"; then
        echo ""
        printf "  ${CYA}${BOLD}NVMe Specific Attributes:${R}\n"
        declare -A nvme_labels=(
            ["percentage_used"]="Percentage Used (%)"
            ["available_spare"]="Available Spare (%)"
            ["media_errors"]="Media Errors (0 = good)"
            ["num_err_log_entries"]="Error Log Entries"
            ["controller_busy_time"]="Controller Busy Time (min)"
        )
        for nk in "${!nvme_labels[@]}"; do
            local nval; nval=$(echo "$smart_out" | grep -i "$nk" | awk '{print $NF}' | head -1)
            [[ -z "$nval" ]] && continue
            local nc="$GRN"
            [[ "$nk" == "percentage_used" && "$nval" -gt 80 ]] && nc="$RED"
            [[ "$nk" == "media_errors" && "$nval" -gt 0 ]] && { nc="$RED"; ((CNT_SMART_FAIL++)); }
            [[ "$nk" == "available_spare" && "$nval" -lt 20 ]] && nc="$YEL"
            printf "  ${nc}${BOLD}  %-40s${R}  ${WHT}%s${R}\n" "${nvme_labels[$nk]}" "$nval"
        done
    fi

    echo ""
    printf "  ${GRY}Full report: sudo smartctl -a %s${R}\n" "$disk"
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
            "(error|fail|warn|critical|panic|timeout|oom|killed|lockup|bug:|hang|denied|flood|corrupt|unable|refused|missing|invalid|abort|mce|edac|segfault|disconnect|overrun|reallocated|uncorrectable)"; then
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
    kv "Hostname"    "$(hostname 2>/dev/null || echo unknown)"
    kv "Kernel"      "$(uname -r 2>/dev/null || echo unknown)"
    kv "OS"          "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo Linux)"
    kv "Uptime"      "$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown)"
    kv "Scan Time"   "$(date '+%d %b %Y  %H:%M:%S %Z')"
    kv "Run As"      "$(whoami 2>/dev/null || echo unknown)"
    kv "SMART Disk"  "$SMART_DISK"
    kv "Report"      "$REPORT_FILE"
    echo ""
    [[ ${EUID:-1} -ne 0 ]] && \
        printf "  ${YEL}⚠  Run with sudo for complete access (SMART, kern.log, auth.log).${R}\n\n"
    hr "-" "$DGR"
}

# ==============================================================================
#  SYSTEM HEALTH SNAPSHOT
# ==============================================================================
system_health() {
    box_header "SYSTEM HEALTH SNAPSHOT" "$GRN"

    # RAM
    if cmd_ok free; then
        local mpct; mpct=$(free 2>/dev/null | awk '/^Mem:/{printf "%.0f",$3/$2*100}')
        local minfo; minfo=$(free -h 2>/dev/null | awk '/^Mem:/{print "Used:"$3" / Total:"$2"  Free:"$4}')
        kv "Memory" "$minfo"
        local fill=$(( mpct * 36 / 100 ))
        local empty=$(( 36 - fill ))
        local mc="$GRN"
        [[ $mpct -gt 75 ]] && mc="$YEL"
        [[ $mpct -gt 90 ]] && mc="$RED"
        printf "  ${mc}  RAM ["; printf '%*s' "$fill" '' | tr ' ' '#'
        printf "${GRY}"; printf '%*s' "$empty" '' | tr ' ' '-'
        printf "${mc}] %s%%${R}\n" "$mpct"
        local swap; swap=$(free -h 2>/dev/null | awk '/^Swap:/{print "Used:"$3" / Total:"$2}')
        kv "Swap" "${swap:-none}"
    fi

    # Load
    cmd_ok uptime && kv "Load Avg" "$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | tr -d ' ')"

    # CPU Temperature
    if cmd_ok sensors; then
        local cpu_temp; cpu_temp=$(sensors 2>/dev/null | grep -iE "(core 0|cpu temp|tdie|tccd)" | head -1 | awk '{print $3}' || echo "N/A")
        kv "CPU Temp" "$cpu_temp"
    fi

    # Disk usage
    echo ""
    printf "  ${CYA}${BOLD}Disk Usage:${R}\n"
    df -h --output=source,size,used,avail,pcent,target 2>/dev/null \
        | grep -v "^Filesystem\|tmpfs\|udev\|overlay\|squashfs" \
        | while IFS= read -r dl; do
        local pct; pct=$(echo "$dl" | awk '{gsub(/%/,"",$5); print $5+0}')
        local dc="$GRN"
        [[ $pct -gt 70 ]] && dc="$YEL"
        [[ $pct -gt 90 ]] && dc="$RED"
        printf "  ${dc}  %s${R}\n" "$dl"
    done

    # Top memory consumers
    echo ""
    printf "  ${CYA}${BOLD}Top Memory Consumers:${R}\n"
    ps aux --sort=-%mem 2>/dev/null | awk 'NR>1 && NR<=6 {printf "    %s%%  %s\n", $4, $11}' \
        | while IFS= read -r pl; do printf "  ${GRY}  %s${R}\n" "$pl"; done

    # Recent kernel messages
    echo ""
    printf "  ${CYA}${BOLD}Last 3 Kernel Messages:${R}\n"
    dmesg 2>/dev/null | tail -3 | while IFS= read -r km; do
        printf "  ${DIM}${GRY}  %s${R}\n" "$km"
    done
}

# ==============================================================================
#  LIVE SYSTEM SCAN — PRIMARY TOOLS + FULL OS COVERAGE
# ==============================================================================
run_system_scan() {
    local mode="${1:-full}"

    # ══════════════════════════════════════════════════════════════════════════
    #  1. journalctl -p err -b --no-pager   (ALL ERRORS SINCE LAST BOOT)
    # ══════════════════════════════════════════════════════════════════════════
    if cmd_ok journalctl; then
        box_header "journalctl -p err -b --no-pager  [ ALL ERRORS SINCE LAST BOOT ]" "$RED"
        local jlines=()
        while IFS= read -r l; do jlines+=("$l"); done < <(
            journalctl -p err -b --no-pager --output=short-precise 2>/dev/null \
                | grep -v "^--" | tail -n "$LOG_LINES" || true
        )
        if [[ ${#jlines[@]} -eq 0 ]]; then
            printf "\n  ${GRN}✔  No errors in journal since last boot.${R}\n"
        else
            for line in "${jlines[@]+"${jlines[@]}"}"; do
                [[ -z "$line" ]] && continue
                if echo "${line,,}" | grep -qE \
                    "(error|fail|warn|critical|emerg|alert|panic|oom|segfault|timeout|lockup|bug:|hang|denied|abort|mce|edac|reallocated|uncorrectable)"; then
                    local parsed; parsed=$(explain_line "$line")
                    IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
                    display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
                fi
            done
        fi
    fi

    # ══════════════════════════════════════════════════════════════════════════
    #  2. systemctl --failed   (ALL FAILED SERVICES)
    # ══════════════════════════════════════════════════════════════════════════
    if cmd_ok systemctl; then
        box_header "systemctl --failed  [ ALL FAILED SERVICES ]" "$RED"
        local fsvc; fsvc=$(systemctl --failed --no-legend --no-pager 2>/dev/null || true)
        if [[ -z "$fsvc" ]]; then
            printf "\n  ${GRN}✔  All services running normally.${R}\n"
        else
            echo "$fsvc" | while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local unit; unit=$(echo "$line" | awk '{print $1}')
                printf "\n  ${RED}${BOLD}✘ FAILED:${R} ${WHT}%s${R}\n" "$unit"
                ((CNT_CRIT++)); ((CNT_TOTAL++)); ((CNT_SERVICES_FAILED++))
                printf "  ${GRN}Fix:${R}  journalctl -u %s -n 30 --no-pager  |  sudo systemctl restart %s\n" "$unit" "$unit"
                printf "  ${GRY}Last 5 log lines:${R}\n"
                journalctl -u "$unit" -n 5 --no-pager 2>/dev/null | grep -v "^--" \
                    | while IFS= read -r jl; do printf "    ${DIM}${GRY}%s${R}\n" "$jl"; done
            done
        fi
    fi

    [[ "$mode" == "quick" ]] && return

    # ══════════════════════════════════════════════════════════════════════════
    #  3. dmesg -T --level=err,crit   (KERNEL ERRORS WITH TIMESTAMPS)
    # ══════════════════════════════════════════════════════════════════════════
    if cmd_ok dmesg; then
        box_header "dmesg -T --level=err,crit  [ KERNEL ERRORS WITH TIMESTAMPS ]" "$ORA"
        local dlines=()
        while IFS= read -r l; do dlines+=("$l"); done < <(
            dmesg -T --level=err,crit 2>/dev/null \
                | tail -n "$LOG_LINES" || \
            dmesg --level=err,crit 2>/dev/null \
                | tail -n "$LOG_LINES" || true
        )
        if [[ ${#dlines[@]} -eq 0 ]]; then
            printf "\n  ${GRN}✔  No kernel errors in ring buffer.${R}\n"
        else
            for line in "${dlines[@]+"${dlines[@]}"}"; do
                [[ -z "$line" ]] && continue
                local parsed; parsed=$(explain_line "$line")
                IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
                display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
            done
        fi

        # dmesg warnings
        box_header "dmesg -T --level=warn  [ KERNEL WARNINGS WITH TIMESTAMPS ]" "$YEL"
        local dwlines=()
        while IFS= read -r l; do dwlines+=("$l"); done < <(
            dmesg -T --level=warn 2>/dev/null | tail -n 100 || true
        )
        if [[ ${#dwlines[@]} -eq 0 ]]; then
            printf "\n  ${GRN}✔  No kernel warnings.${R}\n"
        else
            for line in "${dwlines[@]+"${dwlines[@]}"}"; do
                [[ -z "$line" ]] && continue
                if echo "${line,,}" | grep -qE "(warn|timeout|disconnect|link.down|overrun|overflow|firmware|fail)"; then
                    local parsed; parsed=$(explain_line "$line")
                    IFS=$'\t' read -r sev ts cat expl fix raw <<< "$parsed"
                    display_entry "$sev" "$ts" "$cat" "$expl" "$fix" "$raw"
                fi
            done
        fi
    fi

    # ══════════════════════════════════════════════════════════════════════════
    #  4. sudo smartctl -a /dev/sda   (DISK SMART HEALTH)
    # ══════════════════════════════════════════════════════════════════════════
    run_smart_check "$SMART_DISK"

    # Auto-detect and check all NVMe drives
    for nvme_dev in /dev/nvme?; do
        [[ -b "$nvme_dev" ]] && [[ "$nvme_dev" != "$SMART_DISK" ]] && \
            run_smart_check "$nvme_dev"
    done

    # ══════════════════════════════════════════════════════════════════════════
    #  5. Extended OS-wide log coverage (grep-based)
    # ══════════════════════════════════════════════════════════════════════════

    # /var/log/syslog or /var/log/messages
    for f in /var/log/syslog /var/log/messages; do
        [[ -r "$f" ]] || continue
        local slines=()
        while IFS= read -r l; do slines+=("$l"); done < <(
            grep -iE "(error|fail|warn|critical|panic|oom|timeout|lockup|corrupt|segfault|disconnect|abort|mce|edac|ata.*error|buffer.i\/o|bad.sector|reallocated|uncorrectable|hung.task)" \
                "$f" 2>/dev/null | tail -n "$LOG_LINES" || true
        )
        analyze_lines "$(basename "$f")" "${slines[@]+"${slines[@]}"}"
        break
    done

    # /var/log/kern.log
    [[ -r /var/log/kern.log ]] && {
        local klines=()
        while IFS= read -r l; do klines+=("$l"); done < <(
            grep -iE "(error|fail|crit|panic|oops|bug:|lockup|segfault|mce|edac|oom|hung.task|i\/o.error|ata.*error|buffer.i\/o|reallocated|uncorrectable|overrun|overflow)" \
                /var/log/kern.log 2>/dev/null | tail -n "$LOG_LINES" || true
        )
        analyze_lines "kern.log" "${klines[@]+"${klines[@]}"}"
    }

    # /var/log/auth.log or /var/log/secure
    for f in /var/log/auth.log /var/log/secure; do
        [[ -r "$f" ]] || continue
        local alines=()
        while IFS= read -r l; do alines+=("$l"); done < <(
            grep -iE "(failed|failure|invalid|denied|banned|refused|break-in|authentication.failure|sudo.*error|pam|POSSIBLE BREAK-IN)" \
                "$f" 2>/dev/null | tail -n 150 || true
        )
        analyze_lines "Auth/Security ($(basename "$f"))" "${alines[@]+"${alines[@]}"}"
        break
    done

    # /var/log/dpkg.log
    [[ -r /var/log/dpkg.log ]] && {
        local dpkglines=()
        while IFS= read -r l; do dpkglines+=("$l"); done < <(
            grep -iE "(error|fail|abort|conffile|half-configured|half-installed)" \
                /var/log/dpkg.log 2>/dev/null | tail -n 50 || true
        )
        [[ ${#dpkglines[@]} -gt 0 ]] && \
            analyze_lines "dpkg.log" "${dpkglines[@]+"${dpkglines[@]}"}"
    }

    # /var/log/apt/history.log
    [[ -r /var/log/apt/history.log ]] && {
        local aptlines=()
        while IFS= read -r l; do aptlines+=("$l"); done < <(
            grep -iE "(error|fail|abort)" \
                /var/log/apt/history.log 2>/dev/null | tail -n 30 || true
        )
        [[ ${#aptlines[@]} -gt 0 ]] && \
            analyze_lines "apt/history.log" "${aptlines[@]+"${aptlines[@]}"}"
    }

    # Xorg
    for f in /var/log/Xorg.0.log /var/log/Xorg.1.log "$HOME/.local/share/xorg/Xorg.0.log"; do
        [[ -r "$f" ]] || continue
        local xlines=()
        while IFS= read -r l; do xlines+=("$l"); done < <(
            grep -E "\(EE\)|\(WW\)" "$f" 2>/dev/null | tail -n 50 || true
        )
        analyze_lines "Xorg ($(basename "$f"))" "${xlines[@]+"${xlines[@]}"}"
        break
    done

    # /var/log/boot.log
    [[ -r /var/log/boot.log ]] && {
        local blines=()
        while IFS= read -r l; do blines+=("$l"); done < <(
            grep -iE "(fail|error|warn|not started|cannot|unable)" \
                /var/log/boot.log 2>/dev/null | tail -n 50 || true
        )
        analyze_lines "boot.log" "${blines[@]+"${blines[@]}"}"
    }

    # /var/log/fail2ban.log
    [[ -r /var/log/fail2ban.log ]] && {
        local f2blines=()
        while IFS= read -r l; do f2blines+=("$l"); done < <(
            grep -iE "(ban|fail|error)" /var/log/fail2ban.log 2>/dev/null | tail -n 50 || true
        )
        [[ ${#f2blines[@]} -gt 0 ]] && \
            analyze_lines "fail2ban.log" "${f2blines[@]+"${f2blines[@]}"}"
    }

    # Application logs
    declare -A app_logs=(
        ["/var/log/nginx/error.log"]="NGINX"
        ["/var/log/apache2/error.log"]="Apache"
        ["/var/log/mysql/error.log"]="MySQL"
        ["/var/log/docker.log"]="Docker"
        ["/var/log/cups/error_log"]="CUPS"
        ["/var/log/mail.err"]="Mail"
    )
    for fp in "${!app_logs[@]}"; do
        local nm="${app_logs[$fp]}"
        [[ -r "$fp" ]] || continue
        local aplines=()
        while IFS= read -r l; do aplines+=("$l"); done < <(
            grep -iE "(error|fail|crit|warn|panic|abort|denied|timeout)" \
                "$fp" 2>/dev/null | tail -n 50 || true
        )
        [[ ${#aplines[@]} -gt 0 ]] && \
            analyze_lines "$nm" "${aplines[@]+"${aplines[@]}"}"
    done

    # PostgreSQL (glob)
    for pglog in /var/log/postgresql/postgresql-*.log; do
        [[ -r "$pglog" ]] || continue
        local pglines=()
        while IFS= read -r l; do pglines+=("$l"); done < <(
            grep -iE "(error|fatal|panic|fail)" "$pglog" 2>/dev/null | tail -n 50 || true
        )
        [[ ${#pglines[@]} -gt 0 ]] && \
            analyze_lines "PostgreSQL" "${pglines[@]+"${pglines[@]}"}"
        break
    done

    # Snapd journal
    if cmd_ok journalctl; then
        local snaplines=()
        while IFS= read -r l; do snaplines+=("$l"); done < <(
            journalctl -u snapd --no-pager --output=short-precise \
                --since="${JOURNAL_HOURS} hours ago" 2>/dev/null \
                | grep -iE "(error|fail|panic|abort)" | tail -n 30 || true
        )
        [[ ${#snaplines[@]} -gt 0 ]] && \
            analyze_lines "Snapd Journal" "${snaplines[@]+"${snaplines[@]}"}"
    fi

    # Deep-dive journalctl per failed unit
    if cmd_ok journalctl && cmd_ok systemctl; then
        local failed_units
        failed_units=$(systemctl --failed --no-legend --no-pager 2>/dev/null | awk '{print $1}' || true)
        for unit in $failed_units; do
            [[ -z "$unit" ]] && continue
            local ulines=()
            while IFS= read -r l; do ulines+=("$l"); done < <(
                journalctl -u "$unit" -n 80 --no-pager --output=short-precise 2>/dev/null \
                    | grep -v "^--" || true
            )
            [[ ${#ulines[@]} -gt 0 ]] && \
                analyze_lines "Journal: $unit (deep-dive)" "${ulines[@]+"${ulines[@]}"}"
        done
    fi
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
    printf "  ${WHT}${BOLD}%-32s${R}  %s\n"            "Total Issues Analyzed"  "$CNT_TOTAL"
    printf "  ${RED}${BOLD}%-32s${R}  ${RED}%s${R}\n"  "CRITICAL"               "$CNT_CRIT"
    printf "  ${ORA}${BOLD}%-32s${R}  ${ORA}%s${R}\n"  "ERROR"                  "$CNT_ERR"
    printf "  ${YEL}${BOLD}%-32s${R}  ${YEL}%s${R}\n"  "WARNING"                "$CNT_WARN"
    printf "  ${GRN}${BOLD}%-32s${R}  ${GRN}%s${R}\n"  "INFO"                   "$CNT_INFO"
    printf "  ${RED}${BOLD}%-32s${R}  ${RED}%s${R}\n"  "Failed Services"         "$CNT_SERVICES_FAILED"
    printf "  ${RED}${BOLD}%-32s${R}  ${RED}%s${R}\n"  "SMART Disk Issues"      "$CNT_SMART_FAIL"

    local sc="$GRN" si="✔" st="SYSTEM HEALTHY"
    [[ $CNT_WARN           -gt 0 ]] && sc="$YEL" && si="!!" && st="WARNINGS PRESENT"
    [[ $CNT_ERR            -gt 0 ]] && sc="$ORA" && si="XX" && st="ERRORS DETECTED"
    [[ $CNT_CRIT           -gt 0 ]] && sc="$RED" && si="!!" && st="CRITICAL ISSUES FOUND"
    [[ $CNT_SMART_FAIL     -gt 0 ]] && sc="$RED" && si="!!" && st="DISK FAILURE RISK — BACK UP NOW!"
    [[ $CNT_SERVICES_FAILED -gt 0 ]] && sc="$RED" && si="!!" && st="FAILED SERVICES DETECTED"

    echo ""; hr "-" "$DGR"
    printf "\n  ${BOLD}Overall Status:  ${sc}${BOLD}[%s] %s${R}\n\n" "$si" "$st"
    hr "-" "$DGR"; echo ""

    printf "  ${CYA}${BOLD}QUICK COMMANDS (run these for details):${R}\n\n"
    printf "  ${BLU}  journalctl -p err -b --no-pager${R}                     ${GRY}# all errors since last boot${R}\n"
    printf "  ${BLU}  systemctl --failed${R}                                   ${GRY}# list all failed services${R}\n"
    printf "  ${BLU}  dmesg -T --level=err,crit${R}                           ${GRY}# kernel errors with timestamps${R}\n"
    printf "  ${BLU}  sudo smartctl -a %s${R}                         ${GRY}# disk SMART health${R}\n" "$SMART_DISK"
    printf "  ${BLU}  sudo ./linux_error_doctor.sh --watch${R}                ${GRY}# continuous live monitoring${R}\n"
    printf "  ${BLU}  sudo ./linux_error_doctor.sh --smart /dev/nvme0${R}     ${GRY}# check NVMe drive${R}\n"
    printf "  ${BLU}  journalctl -p err -b -u UNIT --no-pager${R}             ${GRY}# errors for a specific service${R}\n"
    printf "  ${BLU}  dmesg -T --level=err,crit | grep -i ata${R}             ${GRY}# disk-specific kernel errors${R}\n"
    printf "  ${BLU}  dmesg -T --level=err,crit | grep -i nvidia${R}          ${GRY}# GPU-specific kernel errors${R}\n"
    printf "  ${BLU}  grep -iE 'error|fail' /var/log/syslog | tail -50${R}    ${GRY}# syslog quick scan${R}\n"
    echo ""
    kv "Report saved" "$REPORT_FILE"
    hr "=" "$BLU"; echo ""
}

# ==============================================================================
#  USAGE
# ==============================================================================
usage() {
    printf "${BOLD}${CYA}Linux ERR Doctor  v%s${R}\n\n" "$VERSION"
    printf "  ${BOLD}Usage:${R}  sudo ./linux_error_doctor.sh [OPTIONS]\n\n"
    printf "  ${GRN}(no args)${R}              Full system scan (all sources)\n"
    printf "  ${GRN}--quick${R}                Fast: journal (-b) + failed services only\n"
    printf "  ${GRN}--stdin${R}                Pipe mode: cat logfile | ./script.sh --stdin\n"
    printf "  ${GRN}--file${R} PATH            Analyze a specific log file\n"
    printf "  ${GRN}--watch${R}                Continuous live monitoring (%ss refresh)\n" "$WATCH_INTERVAL"
    printf "  ${GRN}--smart${R} /dev/sdX       Disk to SMART-check (default: %s)\n" "$SMART_DISK"
    printf "  ${GRN}--hours${R} N              Journal lookback hours (default: %s)\n" "$JOURNAL_HOURS"
    printf "  ${GRN}--lines${R} N              Lines per log source (default: %s)\n" "$LOG_LINES"
    printf "  ${GRN}--interval${R} N           Watch refresh interval in seconds (default: %s)\n" "$WATCH_INTERVAL"
    printf "  ${GRN}--help${R}                 This help\n\n"
    printf "  ${GRY}Examples:\n"
    printf "    sudo ./linux_error_doctor.sh\n"
    printf "    sudo ./linux_error_doctor.sh --quick\n"
    printf "    sudo ./linux_error_doctor.sh --smart /dev/nvme0\n"
    printf "    sudo ./linux_error_doctor.sh --watch --interval 30\n"
    printf "    cat /var/log/syslog | ./linux_error_doctor.sh --stdin\n"
    printf "    ./linux_error_doctor.sh --file /var/log/syslog${R}\n\n"
}

# ==============================================================================
#  MAIN
# ==============================================================================
main() {
    local mode="full" watch=false use_stdin=false file_path=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick)    mode="quick" ;;
            --watch)    watch=true ;;
            --stdin)    use_stdin=true ;;
            --file)     shift; file_path="$1" ;;
            --smart)    shift; SMART_DISK="$1" ;;
            --hours)    shift; JOURNAL_HOURS="$1" ;;
            --lines)    shift; LOG_LINES="$1" ;;
            --interval) shift; WATCH_INTERVAL="$1" ;;
            --help|-h)  usage; exit 0 ;;
            *)          printf "${RED}Unknown option: %s${R}\n" "$1"; usage; exit 1 ;;
        esac
        shift
    done

    mkdir -p "$REPORT_DIR"

    run_full() {
        CNT_CRIT=0; CNT_ERR=0; CNT_WARN=0; CNT_INFO=0; CNT_TOTAL=0
        CNT_SMART_FAIL=0; CNT_SERVICES_FAILED=0
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
            printf "\n  ${GRY}⟳  Refreshing in ${WATCH_INTERVAL}s... Ctrl+C to stop.${R}\n"
            sleep "$WATCH_INTERVAL"
        done
    else
        run_full
    fi
}

main "$@"
