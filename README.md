ESP8266 Wi‑Fi Scanner + 802.11 Packet Sniffer
================================================

This project provides an ESP8266 firmware that can:

- Scan nearby Wi‑Fi networks (channels, RSSI, encryption, BSSID, SSID)
- Sniff 802.11 frames in promiscuous mode with channel hopping
- Passively detect deauthentication and disassociation management frames
- Built‑in SoftAP web UI at `http://192.168.4.1/` (SSID: `ESP8266-Sniffer`)
- **NEW**: Active deauthentication frame testing capabilities

Hardware
--------
- Any ESP8266 dev board (e.g. NodeMCU v2/v3, Wemos D1 mini)
- USB cable

Quick Start (PlatformIO)
------------------------
1. Install PlatformIO (VS Code extension or `pipx install platformio`)
2. Connect your ESP8266 via USB
3. From this folder run:

   ```bash
   pio run -t upload && pio device monitor
   ```

   The monitor should open at 115200 baud.

Quick Start (Arduino IDE)
-------------------------
If you prefer the Arduino IDE:

1. Install the ESP8266 core for Arduino IDE.
   - In Arduino IDE, open Preferences and add this Boards Manager URL: `https://arduino.esp8266.com/stable/package_esp8266com_index.json`.
   - Open Tools → Board → Boards Manager…, search for "ESP8266 by ESP8266 Community" and install.
2. Open `esp8266_wifi_scan_sniffer/esp8266_wifi_scan_sniffer.ino` in the Arduino IDE.
3. Select the board: Tools → Board → ESP8266 Boards → "Generic ESP8266 Module".
4. Select the correct serial Port under Tools → Port.
5. Upload the sketch, then open the Serial Monitor at 115200 baud.

Serial Commands
---------------
- `s`: Scan networks
- `p`: Start sniffing (promiscuous mode + channel hopping)
- `x`: Stop sniffing
- `cN`: Lock to channel N (1–14), e.g. `c6`
- `h`: Re‑enable channel hopping

Web UI
------
- After flashing, connect to the Wi‑Fi network `ESP8266-Sniffer` (open).
- Browse to `http://192.168.4.1/`.
- Controls available:
  - Start/Stop sniffer
  - Set channel, enable/disable hopping
  - Run scan and view results
  - View live counters for Deauth/Disassoc frames and PPS
  - **NEW**: Deauthentication Test section for active frame testing

Notes and Limitations
---------------------
- Sniffing requires station mode and no active connection.
- Output is throttled to avoid watchdog resets.
- Channel hopping default is 4 hops/sec across channels 1–13.
- Promiscuous APIs are part of the ESP8266 SDK and can change across core versions.
- Deauth/Disassoc detection is passive only; this firmware does not transmit frames.
- **NEW**: Deauthentication testing can actively transmit frames for testing purposes.

Deauthentication Testing
------------------------
The firmware now includes active deauthentication frame testing capabilities:

- **Target MAC**: The MAC address of the device to send deauth frames to
- **BSSID MAC**: The MAC address of the access point (BSSID)
- **Rate**: Configurable packet rate (default: 10 packets/second)
- **Start/Stop**: Control the deauthentication test via web UI

**⚠️ WARNING**: This feature is for testing purposes only. Only use on networks you own or have explicit permission to test. Deauthentication attacks can disrupt network connectivity and may be illegal in many jurisdictions.

Legal
-----
Only use this tool on networks you own or have explicit permission to test. You are responsible for complying with local laws and regulations.


