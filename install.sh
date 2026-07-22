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
# /usr/bin is always on sudo's secure_path; /usr/local/bin sometimes is not
BIN_DIRS=("/usr/bin" "/usr/local/bin")
DESKTOP_DIR="/usr/share/applications"

if [[ ! -f "$SCRIPT_DIR/wifiutil-gui.py" ]]; then
    echo "Missing wifiutil-gui.py in $SCRIPT_DIR" >&2
    exit 1
fi

echo "[*] Installing dependencies (aircrack-ng, iw, rfkill, python3-tk)…"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    aircrack-ng iw rfkill python3 python3-tk >/dev/null

echo "[*] Installing to $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"

# Remove old symlinks first — writing through a symlink would overwrite the .py
for BIN_DIR in "${BIN_DIRS[@]}"; do
    rm -f "$BIN_DIR/wifiutil" "$BIN_DIR/wifiutil-gui" "$BIN_DIR/wifiutil-gui-pkexec"
done
rm -f "$INSTALL_DIR/wifiutil" "$INSTALL_DIR/wifiutil-gui"

install -m 0755 "$SCRIPT_DIR/wifiutil.sh"     "$INSTALL_DIR/wifiutil.sh"
install -m 0755 "$SCRIPT_DIR/wifiutil-gui.py" "$INSTALL_DIR/wifiutil-gui.py"

# Verify we installed real Python, not a shell wrapper
if ! head -1 "$INSTALL_DIR/wifiutil-gui.py" | grep -q python; then
    echo "ERROR: $INSTALL_DIR/wifiutil-gui.py does not look like Python. Aborting." >&2
    head -5 "$INSTALL_DIR/wifiutil-gui.py" >&2
    exit 1
fi

# Wrapper scripts in PATH
for BIN_DIR in "${BIN_DIRS[@]}"; do
    mkdir -p "$BIN_DIR"

    cat > "$BIN_DIR/wifiutil" <<'EOF'
#!/usr/bin/env bash
exec /opt/wifiutil/wifiutil.sh "$@"
EOF
    chmod 0755 "$BIN_DIR/wifiutil"

    cat > "$BIN_DIR/wifiutil-gui" <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /opt/wifiutil/wifiutil-gui.py "$@"
EOF
    chmod 0755 "$BIN_DIR/wifiutil-gui"
done

# pkexec launcher for the desktop icon
cat > /usr/bin/wifiutil-gui-pkexec <<'EOF'
#!/usr/bin/env bash
exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    /usr/bin/wifiutil-gui "$@"
EOF
chmod 0755 /usr/bin/wifiutil-gui-pkexec
ln -sfn /usr/bin/wifiutil-gui-pkexec /usr/local/bin/wifiutil-gui-pkexec

# PolicyKit rule
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
    <annotate key="org.freedesktop.policykit.exec.path">/usr/bin/wifiutil-gui</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
EOF

cat > "$DESKTOP_DIR/wifiutil.desktop" <<EOF
[Desktop Entry]
Name=Aircrack-ng GUI Wrapper
Comment=Interface → Monitor → Scan → Target → Capture → Crack
Exec=/usr/bin/wifiutil-gui-pkexec
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
echo "  Or:   sudo python3 /opt/wifiutil/wifiutil-gui.py"
echo
echo "Verify:"
head -1 /opt/wifiutil/wifiutil-gui.py
ls -l /usr/bin/wifiutil-gui /opt/wifiutil/wifiutil-gui.py
