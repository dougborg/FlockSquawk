#include "doctest.h"
#include "ThreatAnalyzer.h"

extern uint32_t mock_millis_value;

// Capture the last ThreatEvent published by the analyzer
static ThreatEvent lastThreat;
static int threatCount;

static void resetCapture() {
    memset(&lastThreat, 0, sizeof(lastThreat));
    threatCount = 0;
    EventBus::subscribeThreat([](const ThreatEvent& t) {
        lastThreat = t;
        threatCount++;
    });
}

// ============================================================
// Helpers
// ============================================================

static WiFiFrameEvent makeWiFiFrame(const char* ssid, int8_t rssi = -60,
                                     uint8_t channel = 6) {
    WiFiFrameEvent f;
    memset(&f, 0, sizeof(f));
    strncpy(f.ssid, ssid, sizeof(f.ssid) - 1);
    f.rssi = rssi;
    f.channel = channel;
    f.frameSubtype = 0x20;
    // Use a unique-ish MAC based on first char so each test gets distinct devices
    f.mac[0] = 0xDE; f.mac[1] = 0xAD;
    f.mac[2] = (uint8_t)ssid[0]; f.mac[3] = (uint8_t)ssid[1];
    f.mac[4] = 0x00; f.mac[5] = 0x01;
    return f;
}

static BluetoothDeviceEvent makeBLEDevice(const char* name = "",
                                           int8_t rssi = -60,
                                           const char* uuid = "") {
    BluetoothDeviceEvent d;
    memset(&d, 0, sizeof(d));
    strncpy(d.name, name, sizeof(d.name) - 1);
    d.rssi = rssi;
    d.hasServiceUUID = (uuid[0] != '\0');
    if (d.hasServiceUUID) {
        strncpy(d.serviceUUID, uuid, sizeof(d.serviceUUID) - 1);
    }
    d.mac[0] = 0xBE; d.mac[1] = 0xEF;
    d.mac[2] = (uint8_t)name[0]; d.mac[3] = (uint8_t)(name[0] ? name[1] : 0);
    d.mac[4] = 0x00; d.mac[5] = 0x02;
    return d;
}

// ============================================================
// WiFi scoring
// ============================================================

TEST_CASE("ThreatAnalyzer: WiFi SSID format match produces threat") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    analyzer.analyzeWiFiFrame(makeWiFiFrame("Flock-a1b2c3", -60));
    CHECK(threatCount == 1);
    CHECK(lastThreat.certainty > 0);
    CHECK(strcmp(lastThreat.radioType, "wifi") == 0);
    CHECK(strcmp(lastThreat.category, "surveillance_device") == 0);
}

TEST_CASE("ThreatAnalyzer: WiFi no-match produces no threat") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    analyzer.analyzeWiFiFrame(makeWiFiFrame("Starbucks WiFi", -60));
    CHECK(threatCount == 0);
}

TEST_CASE("ThreatAnalyzer: WiFi scoring rule removes keyword double-count") {
    // "Flock-a1b2c3" matches both SSID_FORMAT (75) and SSID_KEYWORD (45).
    // The scoring rule subtracts 45 when both fire together.
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // RSSI -60 → rssiModifier = 0
    analyzer.analyzeWiFiFrame(makeWiFiFrame("Flock-a1b2c3", -60));
    REQUIRE(threatCount == 1);
    // Should be 75 (format) + 45 (keyword) - 45 (rule) + 0 (rssi) = 75
    CHECK(lastThreat.certainty == 75);
    CHECK((lastThreat.matchFlags & DET_SSID_FORMAT) != 0);
}

TEST_CASE("ThreatAnalyzer: WiFi RSSI modifier applied") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // "Flock-a1b2c3" at RSSI -30 → format=75, rssi=+10 → 85
    auto frame = makeWiFiFrame("Flock-a1b2c3", -30);
    // Give unique MAC to avoid hitting existing device
    frame.mac[5] = 0x10;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 85);
    CHECK(lastThreat.rssiModifier == 10);
}

TEST_CASE("ThreatAnalyzer: WiFi certainty clamped to 100") {
    // Keyword-only at very close range: 45 + 10 = 55 (no clamp needed)
    // But let's verify format + OUI + close range doesn't exceed 100:
    // format=75, OUI=20, rssi=+10 = 105 → clamped to 100
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto frame = makeWiFiFrame("Flock-a1b2c3", -30);
    // Set a known OUI
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0x99; frame.mac[4] = 0x99; frame.mac[5] = 0x99;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 100);
}

TEST_CASE("ThreatAnalyzer: WiFi certainty clamped to 0 minimum") {
    // OUI alone (20) at RSSI -90 → 20 + (-10) = 10.
    // Can't easily get negative with existing detectors, but verify >= 0.
    // Use a visible SSID that doesn't match any pattern to avoid hidden bonus.
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // MAC OUI match only (weight 20) at RSSI -90 → 20 + (-10) = 10
    auto frame = makeWiFiFrame("SomeRandomNetwork", -90);
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0xBB; frame.mac[4] = 0xBB; frame.mac[5] = 0xBB;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 10);
}

// ============================================================
// shouldAlert logic
// ============================================================

TEST_CASE("ThreatAnalyzer: shouldAlert true on first high-certainty detection") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    analyzer.analyzeWiFiFrame(makeWiFiFrame("Flock-a1b2c3", -60));
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.shouldAlert == true);
    CHECK(lastThreat.certainty >= ALERT_THRESHOLD);
}

TEST_CASE("ThreatAnalyzer: shouldAlert false on repeat detection") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto frame = makeWiFiFrame("Flock-a1b2c3", -60);
    frame.mac[5] = 0x20;  // unique MAC
    analyzer.analyzeWiFiFrame(frame);
    CHECK(lastThreat.shouldAlert == true);

    // Same device again
    mock_millis_value = 6000;
    analyzer.analyzeWiFiFrame(frame);
    CHECK(lastThreat.shouldAlert == false);
}

TEST_CASE("ThreatAnalyzer: shouldAlert false when below threshold") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // OUI-only match at weak signal: certainty = 20 + (-10) = 10
    auto frame = makeWiFiFrame("", -90);
    frame.ssid[0] = '\0';
    frame.mac[0] = 0xCC; frame.mac[1] = 0xCC; frame.mac[2] = 0xCC;
    frame.mac[3] = 0xAA; frame.mac[4] = 0xAA; frame.mac[5] = 0xAA;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.shouldAlert == false);
}

// ============================================================
// BLE scoring
// ============================================================

TEST_CASE("ThreatAnalyzer: BLE Raven UUID produces acoustic_detector category") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto device = makeBLEDevice("", -60, "00003100-0000-1000-8000-00805f9b34fb");
    device.mac[5] = 0x30;
    analyzer.analyzeBluetoothDevice(device);
    REQUIRE(threatCount == 1);
    CHECK(strcmp(lastThreat.category, "acoustic_detector") == 0);
    CHECK(strcmp(lastThreat.radioType, "bluetooth") == 0);
    CHECK(lastThreat.channel == 0);
}

TEST_CASE("ThreatAnalyzer: BLE name-only produces surveillance_device category") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto device = makeBLEDevice("Flock Tracker", -60);
    device.mac[5] = 0x40;
    analyzer.analyzeBluetoothDevice(device);
    REQUIRE(threatCount == 1);
    CHECK(strcmp(lastThreat.category, "surveillance_device") == 0);
}

TEST_CASE("ThreatAnalyzer: BLE no-match produces no threat") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto device = makeBLEDevice("AirPods Pro", -60);
    device.mac[5] = 0x50;
    analyzer.analyzeBluetoothDevice(device);
    CHECK(threatCount == 0);
}

// ============================================================
// Heartbeat tick
// ============================================================

TEST_CASE("ThreatAnalyzer: tick returns false when no devices tracked") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    CHECK_FALSE(analyzer.tick(0));
    CHECK_FALSE(analyzer.tick(HEARTBEAT_INTERVAL_MS));
}

TEST_CASE("ThreatAnalyzer: tick returns true when high-confidence device in range") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 1000;

    // Inject a high-certainty device
    auto frame = makeWiFiFrame("Flock-a1b2c3", -60);
    frame.mac[5] = 0x60;
    analyzer.analyzeWiFiFrame(frame);
    // Second detection to move to IN_RANGE
    mock_millis_value = 2000;
    analyzer.analyzeWiFiFrame(frame);

    // First tick at heartbeat interval should fire
    bool heartbeat = analyzer.tick(HEARTBEAT_INTERVAL_MS);
    CHECK(heartbeat == true);
}

TEST_CASE("ThreatAnalyzer: tick returns false before heartbeat interval") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 1000;

    auto frame = makeWiFiFrame("Flock-a1b2c3", -60);
    frame.mac[5] = 0x70;
    analyzer.analyzeWiFiFrame(frame);
    mock_millis_value = 2000;
    analyzer.analyzeWiFiFrame(frame);

    // Tick before interval elapses
    CHECK_FALSE(analyzer.tick(HEARTBEAT_INTERVAL_MS - 1));
}

// ============================================================
// Hidden SSID + OUI scoring rule
// ============================================================

TEST_CASE("ThreatAnalyzer: hidden SSID + known OUI triggers alert at close range") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // Hidden SSID (empty string) + known OUI at RSSI -45 (close)
    // OUI=20, hidden-SSID bonus=+50, RSSI mod=+10 → 80
    auto frame = makeWiFiFrame("", -45);
    frame.ssid[0] = '\0';
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0xC0; frame.mac[4] = 0xC0; frame.mac[5] = 0xC0;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 80);
    CHECK(lastThreat.shouldAlert == true);
}

TEST_CASE("ThreatAnalyzer: hidden SSID + known OUI triggers alert at medium range") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // Hidden SSID + known OUI at RSSI -60 (medium)
    // OUI=20, hidden-SSID bonus=+50, RSSI mod=0 → 70
    auto frame = makeWiFiFrame("", -60);
    frame.ssid[0] = '\0';
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0xC1; frame.mac[4] = 0xC1; frame.mac[5] = 0xC1;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 70);
    CHECK(lastThreat.shouldAlert == true);
}

TEST_CASE("ThreatAnalyzer: hidden SSID + known OUI at threshold boundary") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // Hidden SSID + known OUI at RSSI -75 (weaker)
    // OUI=20, hidden-SSID bonus=+50, RSSI mod=-5 → 65
    auto frame = makeWiFiFrame("", -75);
    frame.ssid[0] = '\0';
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0xC2; frame.mac[4] = 0xC2; frame.mac[5] = 0xC2;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 65);
    CHECK(lastThreat.shouldAlert == true);
}

TEST_CASE("ThreatAnalyzer: hidden SSID + known OUI below threshold at long range") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // Hidden SSID + known OUI at RSSI -90 (far)
    // OUI=20, hidden-SSID bonus=+50, RSSI mod=-10 → 60
    auto frame = makeWiFiFrame("", -90);
    frame.ssid[0] = '\0';
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0xC3; frame.mac[4] = 0xC3; frame.mac[5] = 0xC3;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 60);
    CHECK(lastThreat.shouldAlert == false);
}

TEST_CASE("ThreatAnalyzer: visible SSID + known OUI does not get hidden bonus") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    // Non-hidden SSID with known OUI: only OUI weight applies (no bonus)
    // OUI=20, RSSI -60 mod=0 → 20
    auto frame = makeWiFiFrame("SomeNetwork", -60);
    frame.mac[0] = 0x58; frame.mac[1] = 0x8E; frame.mac[2] = 0x81;
    frame.mac[3] = 0xC4; frame.mac[4] = 0xC4; frame.mac[5] = 0xC4;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK(lastThreat.certainty == 20);
    CHECK(lastThreat.shouldAlert == false);
}

// ============================================================
// Flock Safety OUI (B4:1E:52)
// ============================================================

TEST_CASE("ThreatAnalyzer: WiFi B4:1E:52 Flock Safety OUI detected") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto frame = makeWiFiFrame("SomeSSID", -60);
    frame.mac[0] = 0xB4; frame.mac[1] = 0x1E; frame.mac[2] = 0x52;
    frame.mac[3] = 0xAA; frame.mac[4] = 0xBB; frame.mac[5] = 0xCC;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK((lastThreat.matchFlags & DET_FLOCK_OUI) != 0);
    CHECK(lastThreat.shouldAlert == true);
}

TEST_CASE("ThreatAnalyzer: BLE B4:1E:52 Flock Safety OUI detected") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto device = makeBLEDevice("", -60);
    device.mac[0] = 0xB4; device.mac[1] = 0x1E; device.mac[2] = 0x52;
    device.mac[3] = 0xDD; device.mac[4] = 0xEE; device.mac[5] = 0xFF;
    analyzer.analyzeBluetoothDevice(device);
    REQUIRE(threatCount == 1);
    CHECK((lastThreat.matchFlags & DET_FLOCK_OUI) != 0);
    CHECK(lastThreat.shouldAlert == true);
}

TEST_CASE("ThreatAnalyzer: test_flck keyword triggers detection") {
    ThreatAnalyzer analyzer;
    analyzer.initialize();
    resetCapture();
    mock_millis_value = 5000;

    auto frame = makeWiFiFrame("test_flck", -60);
    frame.mac[3] = 0xF1; frame.mac[4] = 0xF2; frame.mac[5] = 0xF3;
    analyzer.analyzeWiFiFrame(frame);
    REQUIRE(threatCount == 1);
    CHECK((lastThreat.matchFlags & DET_SSID_KEYWORD) != 0);
}
