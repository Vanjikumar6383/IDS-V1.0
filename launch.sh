#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║          IDS v1.0 — INTRUSION DETECTION SYSTEM LAUNCHER           ║
# ║              SOC Analyst Tool for Kali Linux                ║
# ╚══════════════════════════════════════════════════════════════╝

SCRIPT_DIR="$( cd "$( dirname "$(realpath "${BASH_SOURCE[0]}")" )" && pwd )"
PY_SCRIPT="$SCRIPT_DIR/ids_engine.py"

# Colors
RED='\033[91m'
GRN='\033[92m'
YEL='\033[93m'
MAG='\033[95m'
CYN='\033[96m'
WHT='\033[97m'
DIM='\033[2m'
RST='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${MAG}${BOLD}"
echo "  ██╗██████╗ ███████╗██╗   ██╗ ██╗    ██████╗ "
echo "  ██║██╔══██╗██╔════╝██║   ██║███║   ██╔═══██╗"
echo "  ██║██║  ██║███████╗██║   ██║╚██║   ██║   ██║"
echo "  ██║██║  ██║╚════██║╚██╗ ██╔╝ ██║   ██║   ██║"
echo "  ██║██████╔╝███████║ ╚████╔╝  ██║██╗╚██████╔╝"
echo "  ╚═╝╚═════╝ ╚══════╝  ╚═══╝   ╚═╝╚═╝ ╚═════╝ "
echo -e "${RST}"
echo -e "  ${CYN}INTRUSION DETECTION SYSTEM — Kali Linux SOC Tool${RST}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "  ${RED}[!] Root privileges required.${RST}"
  echo -e "  ${YEL}    Relaunching with sudo...${RST}"
  echo ""
  exec sudo bash "$(realpath "$0")" "$@"
fi

echo -e "  ${DIM}[*]${RST} Checking dependencies..."

# Check Python3
if ! command -v python3 &> /dev/null; then
  echo -e "  ${RED}[!] python3 not found. Install it: apt install python3${RST}"
  exit 1
fi
echo -e "  ${GRN}[✓]${RST} Python3 found"

# Check nmap (optional but recommended)
if command -v nmap &> /dev/null; then
  echo -e "  ${GRN}[✓]${RST} nmap found — fast network scanning enabled"
else
  echo -e "  ${YEL}[!]${RST} nmap not found — using ping scan (slower)"
  echo -e "      Install: ${DIM}apt install nmap${RST}"
fi

# Check iptables
if command -v iptables &> /dev/null; then
  echo -e "  ${GRN}[✓]${RST} iptables found — auto-blocking enabled"
else
  echo -e "  ${YEL}[!]${RST} iptables not found — auto-blocking disabled"
fi

echo ""
echo -e "  ${MAG}══════════════ LAUNCH OPTIONS ══════════════${RST}"
echo ""
echo -e "  ${CYN}[1]${RST} Start with auto-detected interface"
echo -e "  ${CYN}[2]${RST} Specify interface manually"
echo -e "  ${CYN}[3]${RST} Specify network CIDR manually"
echo -e "  ${CYN}[4]${RST} Start without opening browser"
echo -e "  ${CYN}[5]${RST} Full options (manual)"
echo -e "  ${RED}[q]${RST} Quit"
echo ""
echo -ne "  ${WHT}Select option [1]:${RST} "
read -r choice

case "$choice" in
  2)
    echo -ne "  ${CYN}Interface (e.g. eth0, wlan0):${RST} "
    read -r iface
    exec python3 "$PY_SCRIPT" -i "$iface" "$@"
    ;;
  3)
    echo -ne "  ${CYN}Network CIDR (e.g. 192.168.1.0/24):${RST} "
    read -r net
    exec python3 "$PY_SCRIPT" -n "$net" "$@"
    ;;
  4)
    exec python3 "$PY_SCRIPT" --no-browser "$@"
    ;;
  5)
    echo -ne "  ${CYN}Interface:${RST} "
    read -r iface
    echo -ne "  ${CYN}Network CIDR:${RST} "
    read -r net
    echo -ne "  ${CYN}Dashboard port [8888]:${RST} "
    read -r port
    port=${port:-8888}
    exec python3 "$PY_SCRIPT" -i "$iface" -n "$net" --port "$port" "$@"
    ;;
  q|Q)
    echo -e "  ${YEL}Exiting.${RST}"
    exit 0
    ;;
  *)
    exec python3 "$PY_SCRIPT" "$@"
    ;;
esac
