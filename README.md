# Aircrack-ng GUI Wrapper (Kali)

Step-by-step WiFi audit flow:

**Interface → Monitor → Scan → Target → Capture → Crack**

Use only on networks you own or have written permission to test.

## Install

```bash
chmod +x wifiutil.sh wifiutil-gui.py install.sh
sudo ./install.sh
```

## Run

```bash
sudo wifiutil-gui          # stepped GUI
sudo python3 wifiutil-gui.py

sudo wifiutil              # CLI menu (same tools)
```

## GUI steps

| Step | Action |
|------|--------|
| **1. Interface** | Pick `wlan0` (or USB adapter) → Use selected |
| **2. Monitor** | Enable monitor mode (`airmon-ng check kill` + `iw`) |
| **3. Scan** | Timed `airodump-ng` → list APs |
| **4. Target** | Select AP → Find clients → select station MAC |
| **5. Capture** | Start `airodump-ng -c -w -d` → Deauth client with `aireplay-ng` |
| **6. Crack** | Browse `.cap` + wordlist → `aircrack-ng CAP -w Password.txt` |

**Stop all** kills airodump/aireplay/aircrack and restores managed mode.

## CLI

`wifiutil.sh` still has the menu for the same workflow (scan, clients, deauth, crack).

## Files

- Captures: `/tmp/wifiutil-captures/`
- Scans: `/tmp/wifiutil-scans/`

## Dependencies

`aircrack-ng`, `iw`, `ip`, `rfkill`, `python3-tk`
