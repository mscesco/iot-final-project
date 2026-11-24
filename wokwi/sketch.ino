/*
 * NexaSense - firmware EDUCACIONAL para a disciplina Hardware Hacking (IoT)
 *
 * Simula o protótipo da NexaHome: ESP32 + DHT22, telemetria via MQTT, comando de LED,
 * console de diagnóstico na UART0, endpoint HTTP de status e atualização OTA.
 *
 * ATENÇÃO: o perfil "lab" contém fragilidades INTENCIONAIS, documentadas em
 * findings/findings.md. Uso restrito a placa própria e rede isolada de laboratório.
 *
 * Perfil lab       -> condições inseguras do protótipo (objeto da avaliação)
 * Perfil hardened  -> mesmas funções com as mitigações de software (objeto do reteste)
 */
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <Preferences.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>

// ---------------------------------------------------------------- perfil de build
// No PlatformIO o perfil vem do platformio.ini. No Wokwi (navegador) não há build flags:
// sem nada definido, compila o perfil "lab". Para o reteste no Wokwi, descomente a linha abaixo.
// #define NEXA_BUILD_HARDENED 1
#if !defined(NEXA_BUILD_LAB) && !defined(NEXA_BUILD_HARDENED)
#define NEXA_BUILD_LAB 1
#endif
#ifndef NEXA_FW_VERSION
#ifdef NEXA_BUILD_HARDENED
#define NEXA_FW_VERSION "1.0.0-hardened"
#else
#define NEXA_FW_VERSION "0.9.3-lab"
#endif
#endif

// ---------------------------------------------------------------- configuração do laboratório
#if __has_include("secrets.h")
#include "secrets.h"
#endif

// Rede virtual do Wokwi: access point aberto "Wokwi-GUEST", canal 6.
#ifndef LAB_WIFI_SSID
#define LAB_WIFI_SSID     "Wokwi-GUEST"
#endif
#ifndef LAB_WIFI_PASS
#define LAB_WIFI_PASS     ""
#endif
// Broker MQTT LOCAL do laboratório: Mosquitto rodando em 127.0.0.1 no notebook.
// No Wokwi for VS Code o gateway embutido resolve "host.wokwi.internal" para o PC
// (o ESP32 simulado recebe 10.13.37.x). Nenhum serviço externo é usado.
// Porta 1883 = MQTT sem TLS com usuário/senha. A conta de laboratório abaixo representa
// "a credencial da frota" compartilhada e embutida no firmware (fragilidade F04).
#ifndef LAB_MQTT_HOST
#define LAB_MQTT_HOST     "host.wokwi.internal"
#endif
#ifndef LAB_MQTT_PORT
#define LAB_MQTT_PORT     1883
#endif
#ifndef LAB_MQTT_USER
#define LAB_MQTT_USER     "nexasense"
#endif
#ifndef LAB_MQTT_PASS
#define LAB_MQTT_PASS     "nexa-fleet-7p2q"
#endif
// Raiz de tópicos da frota. Como o broker é local e isolado, usamos uma raiz fixa
// que casa com a ACL de lab/mosquitto/acl (nexahome/#).
#ifndef LAB_TOPIC_ROOT
#define LAB_TOPIC_ROOT    "nexahome"
#endif
// Perfil hardened: 8883 = MQTT sobre TLS + usuário/senha (listener TLS do Mosquitto local).
#ifndef HARD_MQTT_PORT
#define HARD_MQTT_PORT    8883
#endif

#ifdef NEXA_BUILD_HARDENED
#if __has_include("ca_cert.h")
#include "ca_cert.h"
#else
// CA do laboratório, gerada por lab/mosquitto/gen-certs.sh
static const char NEXA_CA_CERT[] = R"EOF(
-----BEGIN CERTIFICATE-----
COLE AQUI O CERTIFICADO DA CA
-----END CERTIFICATE-----
)EOF";
#endif
#endif

// ---------------------------------------------------------------- hardware
static const uint8_t PIN_DHT = 4;    // DATA do DHT22 (com pull-up 10k para 3V3)
static const uint8_t PIN_LED = 2;    // LED do atuador (externo no Wokwi; onboard no DevKit V1)
static const uint8_t DHT_TYPE = DHT22;

DHT dht(PIN_DHT, DHT_TYPE);
Preferences prefs;
WebServer http(80);

#ifdef NEXA_BUILD_HARDENED
WiFiClientSecure netClient;
#else
WiFiClient netClient;
#endif
PubSubClient mqtt(netClient);

// ---------------------------------------------------------------- configuração
struct Config {
  String wifiSsid;
  String wifiPass;
  String mqttHost;
  uint16_t mqttPort;
  String mqttUser;
  String mqttPass;
  uint32_t intervalSec;
  bool provisioned;
};

Config cfg;
String deviceId;
String topicTelemetry, topicStatus, topicCmd;
uint32_t lastPublish = 0;
bool ledState = false;
String serialBuffer;

static const char *NVS_NS = "nexacfg";

// ---------------------------------------------------------------- utilidades
String macSuffix() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char buf[7];
  snprintf(buf, sizeof(buf), "%02X%02X%02X", mac[3], mac[4], mac[5]);
  return String(buf);
}

void buildTopics() {
  String root = String(LAB_TOPIC_ROOT) + "/" + deviceId;
  topicTelemetry = root + "/telemetry";
  topicStatus    = root + "/status";
  topicCmd       = root + "/cmd";
}

void setLed(bool on) {
  ledState = on;
  digitalWrite(PIN_LED, on ? HIGH : LOW);
}

// ---------------------------------------------------------------- NVS
void saveConfig() {
  prefs.begin(NVS_NS, false);
  // Perfil lab: parâmetros (inclusive senhas) gravados em texto claro na partição NVS.
  // Sem Flash Encryption / NVS Encryption, qualquer dump da Flash revela esses valores.
  prefs.putString("wifi_ssid", cfg.wifiSsid);
  prefs.putString("wifi_pass", cfg.wifiPass);
  prefs.putString("mqtt_host", cfg.mqttHost);
  prefs.putUShort("mqtt_port", cfg.mqttPort);
  prefs.putString("mqtt_user", cfg.mqttUser);
  prefs.putString("mqtt_pass", cfg.mqttPass);
  prefs.putUInt("interval", cfg.intervalSec);
  prefs.putBool("provisioned", cfg.provisioned);
  prefs.end();
}

void loadConfig() {
  prefs.begin(NVS_NS, true);
  bool exists = prefs.isKey("provisioned");
  if (exists) {
    cfg.wifiSsid    = prefs.getString("wifi_ssid", "");
    cfg.wifiPass    = prefs.getString("wifi_pass", "");
    cfg.mqttHost    = prefs.getString("mqtt_host", "");
    cfg.mqttPort    = prefs.getUShort("mqtt_port", 1883);
    cfg.mqttUser    = prefs.getString("mqtt_user", "");
    cfg.mqttPass    = prefs.getString("mqtt_pass", "");
    cfg.intervalSec = prefs.getUInt("interval", 10);
    cfg.provisioned = prefs.getBool("provisioned", false);
  }
  prefs.end();

  if (!exists) {
#ifdef NEXA_BUILD_LAB
    // Perfil lab: primeiro boot carrega os padrões embutidos no binário (credencial compartilhada).
    cfg.wifiSsid    = LAB_WIFI_SSID;
    cfg.wifiPass    = LAB_WIFI_PASS;
    cfg.mqttHost    = LAB_MQTT_HOST;
    cfg.mqttPort    = LAB_MQTT_PORT;
    cfg.mqttUser    = LAB_MQTT_USER;
    cfg.mqttPass    = LAB_MQTT_PASS;
    cfg.intervalSec = 10;
    cfg.provisioned = true;
#else
    // Perfil hardened: nenhum segredo no binário. O dispositivo nasce "não provisionado"
    // e recebe credenciais únicas na etapa de fabricação (comando provision).
    cfg.wifiSsid = "";
    cfg.wifiPass = "";
    cfg.mqttHost = LAB_MQTT_HOST;
    cfg.mqttPort = HARD_MQTT_PORT;
    cfg.mqttUser = "";
    cfg.mqttPass = "";
    cfg.intervalSec = 10;
    cfg.provisioned = false;
#endif
    saveConfig();
  }
}

void factoryReset() {
  prefs.begin(NVS_NS, false);
  prefs.clear();
  prefs.end();
  Serial.println(F("[nexa] factory reset concluido, reiniciando..."));
  delay(300);
  ESP.restart();
}

// ---------------------------------------------------------------- banner de boot
void printBootBanner() {
  Serial.println();
  Serial.println(F("========================================"));
  Serial.printf("  NexaSense  fw %s\n", NEXA_FW_VERSION);
  Serial.println(F("========================================"));
#ifdef NEXA_BUILD_LAB
  // Fragilidade intencional (F01): log de inicialização verboso, com detalhes internos.
  Serial.printf("[boot] build: %s %s\n", __DATE__, __TIME__);
  Serial.printf("[boot] chip: %s rev %d, %d cores, flash %u bytes\n",
                ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores(),
                ESP.getFlashChipSize());
  Serial.printf("[boot] device_id=%s mac=%s\n", deviceId.c_str(), WiFi.macAddress().c_str());
  Serial.printf("[boot] wifi_ssid=%s\n", cfg.wifiSsid.c_str());
  Serial.printf("[boot] mqtt=%s:%u user=%s\n", cfg.mqttHost.c_str(), cfg.mqttPort,
                cfg.mqttUser.c_str());
  Serial.printf("[boot] topics: %s | %s\n", topicTelemetry.c_str(), topicCmd.c_str());
  Serial.println(F("[boot] ota: http (sem assinatura), console de diagnostico: ATIVO"));
  Serial.println(F("[boot] digite 'help' para comandos de manutencao"));
#else
  Serial.printf("device %s\n", deviceId.c_str());
  if (!cfg.provisioned) Serial.println(F("estado: NAO PROVISIONADO (modo fabrica)"));
#endif
}

// ---------------------------------------------------------------- OTA
void doOta(const String &url) {
  Serial.printf("[ota] baixando %s\n", url.c_str());
  mqtt.publish(topicStatus.c_str(), "updating", true);
#ifdef NEXA_BUILD_LAB
  // Fragilidade intencional (F07): OTA por HTTP puro, sem autenticação da origem,
  // sem verificação de assinatura e sem checagem de versão (permite rollback).
  WiFiClient otaClient;
  t_httpUpdate_return r = httpUpdate.update(otaClient, url);
#else
  // Hardened: exige HTTPS com a CA do laboratório. A assinatura da imagem deve ser
  // garantida por Secure Boot V2 na versão de produção (ver remediation/hardening-plan.md).
  if (!url.startsWith("https://")) {
    Serial.println(F("[ota] recusado: apenas https"));
    return;
  }
  WiFiClientSecure otaClient;
  otaClient.setCACert(NEXA_CA_CERT);
  httpUpdate.rebootOnUpdate(true);
  t_httpUpdate_return r = httpUpdate.update(otaClient, url, NEXA_FW_VERSION);
#endif
  switch (r) {
    case HTTP_UPDATE_FAILED:
      Serial.printf("[ota] falhou: %s\n", httpUpdate.getLastErrorString().c_str());
      break;
    case HTTP_UPDATE_NO_UPDATES:
      Serial.println(F("[ota] sem atualizacao"));
      break;
    case HTTP_UPDATE_OK:
      Serial.println(F("[ota] ok"));
      break;
  }
}

// ---------------------------------------------------------------- comandos MQTT
void handleCommand(JsonDocument &doc, const char *origin) {
  if (doc["led"].is<const char *>()) {
    String v = doc["led"].as<String>();
    setLed(v == "on");
    lastPublish = 0;  // publica a telemetria logo em seguida, para o efeito ser observável
    Serial.printf("[cmd/%s] led=%s\n", origin, ledState ? "on" : "off");
  }
  if (doc["interval"].is<uint32_t>()) {
    uint32_t v = doc["interval"].as<uint32_t>();
#ifdef NEXA_BUILD_HARDENED
    if (v < 5 || v > 3600) {
      Serial.println(F("[cmd] interval fora do intervalo permitido (5..3600)"));
      return;
    }
#endif
    cfg.intervalSec = v;
    saveConfig();
    Serial.printf("[cmd/%s] interval=%u\n", origin, v);
  }
  if (doc["reboot"].is<bool>() && doc["reboot"].as<bool>()) {
    Serial.printf("[cmd/%s] reboot\n", origin);
    delay(200);
    ESP.restart();
  }
#ifdef NEXA_BUILD_LAB
  // Fragilidade intencional (F07): qualquer cliente que publique no tópico de comando
  // consegue disparar uma atualização de firmware.
  if (doc["ota"].is<const char *>()) {
    doOta(doc["ota"].as<String>());
  }
#endif
}

void onMqttMessage(char *topic, byte *payload, unsigned int len) {
  String body;
  body.reserve(len);
  for (unsigned int i = 0; i < len; i++) body += (char)payload[i];
#ifdef NEXA_BUILD_LAB
  Serial.printf("[mqtt] rx %s %s\n", topic, body.c_str());
#endif
  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    Serial.println(F("[mqtt] json invalido"));
    return;
  }
  handleCommand(doc, "mqtt");
}

// ---------------------------------------------------------------- rede
bool connectWifi() {
  if (WiFi.status() == WL_CONNECTED) return true;
  if (cfg.wifiSsid.isEmpty()) return false;
  WiFi.mode(WIFI_STA);
  if (cfg.wifiSsid == "Wokwi-GUEST")
    WiFi.begin(cfg.wifiSsid.c_str(), "", 6);  // canal 6 acelera a conexão no simulador
  else
    WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPass.c_str());
  Serial.printf("[wifi] conectando em %s", cfg.wifiSsid.c_str());
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 15000) {
    delay(500);
    Serial.print('.');
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[wifi] ok ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
    return true;
  }
  Serial.println(F("[wifi] falha"));
  return false;
}

bool connectMqtt() {
  if (mqtt.connected()) return true;
  mqtt.setServer(cfg.mqttHost.c_str(), cfg.mqttPort);
#ifdef NEXA_BUILD_LAB
  Serial.printf("[mqtt] conectando %s:%u como %s\n", cfg.mqttHost.c_str(), cfg.mqttPort,
                cfg.mqttUser.c_str());
#endif
  bool ok = mqtt.connect(deviceId.c_str(), cfg.mqttUser.c_str(), cfg.mqttPass.c_str(),
                         topicStatus.c_str(), 1, true, "offline");
  if (ok) {
    mqtt.publish(topicStatus.c_str(), "online", true);
    mqtt.subscribe(topicCmd.c_str());
    Serial.println(F("[mqtt] conectado"));
  } else {
    Serial.printf("[mqtt] falha rc=%d\n", mqtt.state());
  }
  return ok;
}

void publishTelemetry() {
  float t = dht.readTemperature();
  float h = dht.readHumidity();
  JsonDocument doc;
  doc["device"] = deviceId;
  doc["fw"] = NEXA_FW_VERSION;
  if (isnan(t) || isnan(h)) {
    doc["error"] = "sensor_read_failed";
  } else {
    doc["temp"] = serialized(String(t, 1));
    doc["hum"] = serialized(String(h, 1));
  }
  doc["led"] = ledState ? "on" : "off";
  doc["rssi"] = WiFi.RSSI();
  doc["uptime"] = millis() / 1000;
#ifdef NEXA_BUILD_LAB
  doc["ip"] = WiFi.localIP().toString();
  doc["mac"] = WiFi.macAddress();
#endif
  String out;
  serializeJson(doc, out);
  mqtt.publish(topicTelemetry.c_str(), out.c_str());
#ifdef NEXA_BUILD_LAB
  Serial.printf("[tele] %s\n", out.c_str());
#endif
}

// ---------------------------------------------------------------- HTTP (lab)
#ifdef NEXA_BUILD_LAB
void setupHttp() {
  // Fragilidade intencional (F08): endpoint de diagnóstico sem autenticação.
  http.on("/status", HTTP_GET, []() {
    JsonDocument doc;
    doc["device"] = deviceId;
    doc["fw"] = NEXA_FW_VERSION;
    doc["mac"] = WiFi.macAddress();
    doc["ip"] = WiFi.localIP().toString();
    doc["mqtt_host"] = cfg.mqttHost;
    doc["mqtt_port"] = cfg.mqttPort;
    doc["mqtt_user"] = cfg.mqttUser;
    doc["uptime"] = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["chip_rev"] = ESP.getChipRevision();
    String out;
    serializeJson(doc, out);
    http.send(200, "application/json", out);
  });
  http.begin();
  Serial.println(F("[http] servidor de status na porta 80 (/status)"));
}
#endif

// ---------------------------------------------------------------- console serial
void printHelp() {
#ifdef NEXA_BUILD_LAB
  Serial.println(F("comandos: help | status | config | set <chave> <valor> | save | led on|off"));
  Serial.println(F("          ota <url> | reboot | factory"));
  Serial.println(F("chaves:   wifi_ssid wifi_pass mqtt_host mqtt_port mqtt_user mqtt_pass interval"));
#else
  Serial.println(F("comandos: status"));
  if (!cfg.provisioned)
    Serial.println(F("          provision <wifi_ssid> <wifi_pass|-> <mqtt_user> <mqtt_pass>  (somente em fabrica)"));
#endif
}

void printStatus() {
  Serial.printf("fw=%s device=%s wifi=%s mqtt=%s led=%s uptime=%lus\n", NEXA_FW_VERSION,
                deviceId.c_str(), WiFi.status() == WL_CONNECTED ? "ok" : "off",
                mqtt.connected() ? "ok" : "off", ledState ? "on" : "off", millis() / 1000);
}

void handleSerialCommand(String line) {
  line.trim();
  if (line.isEmpty()) return;
  int sp = line.indexOf(' ');
  String cmd = sp < 0 ? line : line.substring(0, sp);
  String arg = sp < 0 ? "" : line.substring(sp + 1);
  arg.trim();

  if (cmd == "help") { printHelp(); return; }
  if (cmd == "status") { printStatus(); return; }

#ifdef NEXA_BUILD_LAB
  // Fragilidade intencional (F02): console sem autenticação. Quem tiver acesso à UART0
  // lê a configuração completa (incluindo senhas) e altera parâmetros.
  if (cmd == "config") {
    Serial.printf("wifi_ssid=%s\nwifi_pass=%s\nmqtt_host=%s\nmqtt_port=%u\n",
                  cfg.wifiSsid.c_str(), cfg.wifiPass.c_str(), cfg.mqttHost.c_str(), cfg.mqttPort);
    Serial.printf("mqtt_user=%s\nmqtt_pass=%s\ninterval=%u\n", cfg.mqttUser.c_str(),
                  cfg.mqttPass.c_str(), cfg.intervalSec);
    return;
  }
  if (cmd == "set") {
    int sp2 = arg.indexOf(' ');
    if (sp2 < 0) { Serial.println(F("uso: set <chave> <valor>")); return; }
    String k = arg.substring(0, sp2), v = arg.substring(sp2 + 1);
    if (k == "wifi_ssid") cfg.wifiSsid = v;
    else if (k == "wifi_pass") cfg.wifiPass = v;
    else if (k == "mqtt_host") cfg.mqttHost = v;
    else if (k == "mqtt_port") cfg.mqttPort = v.toInt();
    else if (k == "mqtt_user") cfg.mqttUser = v;
    else if (k == "mqtt_pass") cfg.mqttPass = v;
    else if (k == "interval") cfg.intervalSec = v.toInt();
    else { Serial.println(F("chave desconhecida")); return; }
    Serial.printf("%s atualizado (use 'save' para persistir)\n", k.c_str());
    return;
  }
  if (cmd == "save") { saveConfig(); Serial.println(F("config salva na NVS")); return; }
  if (cmd == "led") { setLed(arg == "on"); Serial.printf("led=%s\n", ledState ? "on" : "off"); return; }
  if (cmd == "ota") { doOta(arg); return; }
  if (cmd == "reboot") { ESP.restart(); return; }
  if (cmd == "factory") { factoryReset(); return; }
#else
  if (cmd == "provision" && !cfg.provisioned) {
    // provision <ssid> <wifi_pass|-> <mqtt_user> <mqtt_pass>
    // Em produção, usuário/senha (ou certificado) seriam ÚNICOS por unidade, gerados na fábrica.
    // No broker público do laboratório só existem as contas de teste, então a unicidade é
    // documentada como proposta (ver remediation/hardening-plan.md).
    int a = arg.indexOf(' ');
    int b = a < 0 ? -1 : arg.indexOf(' ', a + 1);
    int c = b < 0 ? -1 : arg.indexOf(' ', b + 1);
    if (a < 0 || b < 0 || c < 0) {
      Serial.println(F("uso: provision <ssid> <wifi_pass|-> <mqtt_user> <mqtt_pass>"));
      return;
    }
    cfg.wifiSsid = arg.substring(0, a);
    cfg.wifiPass = arg.substring(a + 1, b);
    if (cfg.wifiPass == "-") cfg.wifiPass = "";
    cfg.mqttUser = arg.substring(b + 1, c);
    cfg.mqttPass = arg.substring(c + 1);
    cfg.provisioned = true;
    saveConfig();
    Serial.println(F("provisionado. console de manutencao bloqueado. reiniciando..."));
    delay(300);
    ESP.restart();
    return;
  }
#endif
  Serial.println(F("comando desconhecido"));
}

void pollSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      handleSerialCommand(serialBuffer);
      serialBuffer = "";
    } else if (serialBuffer.length() < 200) {
      serialBuffer += c;
    }
  }
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(PIN_LED, OUTPUT);
  setLed(false);
  dht.begin();

  WiFi.mode(WIFI_STA);
  deviceId = "nexa-" + macSuffix();
  buildTopics();
  loadConfig();
  printBootBanner();

#ifdef NEXA_BUILD_HARDENED
  netClient.setCACert(NEXA_CA_CERT);
#endif
  mqtt.setBufferSize(1024);
  mqtt.setCallback(onMqttMessage);

  if (cfg.provisioned && connectWifi()) {
#ifdef NEXA_BUILD_LAB
    setupHttp();
#endif
    connectMqtt();
  }
}

void loop() {
  pollSerial();
  if (!cfg.provisioned) { delay(20); return; }

  if (WiFi.status() != WL_CONNECTED) {
    static uint32_t lastTry = 0;
    if (millis() - lastTry > 10000) { lastTry = millis(); connectWifi(); }
  } else {
#ifdef NEXA_BUILD_LAB
    http.handleClient();
#endif
    if (!mqtt.connected()) {
      static uint32_t lastMqtt = 0;
      if (millis() - lastMqtt > 5000) { lastMqtt = millis(); connectMqtt(); }
    } else {
      mqtt.loop();
      if (millis() - lastPublish > cfg.intervalSec * 1000UL) {
        lastPublish = millis();
        publishTelemetry();
      }
    }
  }
  delay(10);
}
