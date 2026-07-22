#!/usr/bin/env bash
#
# install.sh — install WiFi Utility on Kali Linux
# Usage: sudo ./install.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wifiutil"
BIN_DIR="/usr/local/bin"
DESKTOP_DIR="/usr/share/applications"

echo "[*] Installing dependencies (aircrack-ng, iw, rfkill, python3-tk)…"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    aircrack-ng iw rfkill python3 python3-tk >/dev/null

echo "[*] Installing to $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$SCRIPT_DIR/wifiutil.sh"     "$INSTALL_DIR/wifiutil.sh"
install -m 0755 "$SCRIPT_DIR/wifiutil-gui.py" "$INSTALL_DIR/wifiutil-gui.py"

ln -sfn "$INSTALL_DIR/wifiutil.sh"     "$BIN_DIR/wifiutil"
ln -sfn "$INSTALL_DIR/wifiutil-gui.py" "$BIN_DIR/wifiutil-gui"

# pkexec launcher so the desktop icon can request root
cat > "$BIN_DIR/wifiutil-gui-pkexec" <<'EOF'
#!/usr/bin/env bash
exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    /usr/local/bin/wifiutil-gui "$@"
EOF
chmod 0755 "$BIN_DIR/wifiutil-gui-pkexec"

# PolicyKit rule so pkexec can run the GUI
mkdir -p /usr/share/polkit-1/actions
cat > /usr/share/polkit-1/actions/org.kali.wifiutil.policy <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="org.kali.wifiutil.run">
    <description>Run WiFi Utility GUI</description>
    <message>Authentication is required to run WiFi Utility (monitor mode)</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/bin/wifiutil-gui</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
EOF

cat > "$DESKTOP_DIR/wifiutil.desktop" <<EOF
[Desktop Entry]
Name=Aircrack-ng GUI Wrapper
Comment=Interface → Monitor → Scan → Target → Capture → Crack
Exec=wifiutil-gui-pkexec
Icon=network-wireless
Terminal=false
Type=Application
Categories=Network;Security;System;
Keywords=wifi;wireless;aircrack;airodump;
EOF
chmod 0644 "$DESKTOP_DIR/wifiutil.desktop"

echo
echo "Installed."
echo "  GUI:  sudo wifiutil-gui"
echo "  CLI:  sudo wifiutil"
echo "  Or open \"Aircrack-ng GUI Wrapper\" from the application menu."
