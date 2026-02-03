/*
   ESP32 + RDA5807
   Continuous auto-station + ADC entropy password
   
   Modifica: Password generata solo alla pressione del pulsante
   Modifica: Cifratura AES-128 della password

   SDA = GPIO21
   SCL = GPIO22
   ADC = GPIO33 (ADC1_CH5)
   BUTTON = GPIO34
*/

#include <Arduino.h>
#include <Wire.h>
#include <RDA5807.h>
#include "mbedtls/aes.h"
#include <WiFi.h>
#include <Firebase_ESP_Client.h>
#include "time.h"
#include "mbedtls/md.h" 
#include "addons/TokenHelper.h"
#include "addons/RTDBHelper.h"

#define SDA_PIN 21
#define SCL_PIN 22
#define ADC_PIN 33
#define BUTTON_PIN 34

#define NUM_SAMPLES  50
#define STR_LEN      16

// ======================================================
// CONFIGURAZIONE - WiFi e Firebase
// ======================================================
#define WIFI_SSID ""
#define WIFI_PASSWORD ""
#define DATABASE_URL "your_database_url"
#define DATABASE_SECRET "your_database_secret"

RDA5807 rx;
FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;

// Variabili per la Blockchain
String ultimoHash = "0000000000000000000000000000000000000000000000000000000000000000";
String percorsoMeta = "/meta/last_hash";
String percorsoChain = "/chain";

// Variabili per gestione pulsante (debouncing)
volatile bool buttonPressed = false;
unsigned long lastButtonTime = 0;
const unsigned long debounceDelay = 200;

// Chiave AES-128 (16 byte)
const unsigned char aes_key[16] = "secret_key";
const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = 3600;
const int   daylightOffset_sec = 3600;

// IV (Initialization Vector) per CBC - 16 byte
unsigned char aes_iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};


// ======================================================
// ISR per il pulsante
// ======================================================
void IRAM_ATTR buttonISR() {
  buttonPressed = true;
}


// ======================================================
// Cifra una stringa con AES-128-CBC
// ======================================================
int encryptAES128(String password, unsigned char* encrypted) {
  mbedtls_aes_context aes;
  
  int inputLen = password.length();
  int paddedLen = ((inputLen / 16) + 1) * 16;
  
  unsigned char plaintext[paddedLen];
  memset(plaintext, 0, paddedLen);
  memcpy(plaintext, password.c_str(), inputLen);
  
  unsigned char padValue = paddedLen - inputLen;
  for(int i = inputLen; i < paddedLen; i++) {
    plaintext[i] = padValue;
  }
  
  unsigned char iv_copy[16];
  memcpy(iv_copy, aes_iv, 16);
  
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, aes_key, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, iv_copy, plaintext, encrypted);
  mbedtls_aes_free(&aes);
  
  return paddedLen;
}


// ======================================================
// NTP
// ======================================================
void initNTP() {
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  
  Serial.print("Sincronizzazione NTP");
  
  int tentativi = 0;
  while (time(nullptr) < 1000000000 && tentativi < 20) {
    Serial.print(".");
    delay(500);
    tentativi++;
  }
  
  if (time(nullptr) > 1000000000) {
    Serial.println(" OK!");
    struct tm timeinfo;
    if (getLocalTime(&timeinfo)) {
      Serial.print("Data/Ora: ");
      Serial.println(&timeinfo, "%d/%m/%Y %H:%M:%S");
    }
  } else {
    Serial.println(" ERRORE!");
  }
}

unsigned long getTimestamp() {
  return (unsigned long)time(nullptr);
}

String getTimestampString() {
  return String(getTimestamp());
}


// ======================================================
// Stampa HEX
// ======================================================
void printHex(unsigned char* data, int len) {
  for(int i = 0; i < len; i++) {
    if(data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}


// ======================================================
// Stampa Base64
// ======================================================
void printBase64(unsigned char* data, int len) {
  const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  for(int i = 0; i < len; i += 3) {
    unsigned char b0 = data[i];
    unsigned char b1 = (i + 1 < len) ? data[i + 1] : 0;
    unsigned char b2 = (i + 2 < len) ? data[i + 2] : 0;
    
    Serial.print(base64_chars[b0 >> 2]);
    Serial.print(base64_chars[((b0 & 0x03) << 4) | (b1 >> 4)]);
    Serial.print((i + 1 < len) ? base64_chars[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=');
    Serial.print((i + 2 < len) ? base64_chars[b2 & 0x3F] : '=');
  }
  Serial.println();
}


// ======================================================
// Media ADC
// ======================================================
uint16_t adcAvg() {
  uint32_t s = 0;
  for(int i=0; i<NUM_SAMPLES; i++){
    s += analogRead(ADC_PIN);
    delayMicroseconds(50);
  }
  return s / NUM_SAMPLES;
}


// ======================================================
// Genera password da ADC
// ======================================================
String generatePassword() {
  String out;
  out.reserve(STR_LEN);

  for(int i=0; i<STR_LEN; i++){
    uint16_t v = analogRead(ADC_PIN);
    uint8_t  v8 = v >> 4;
    uint8_t  idx = v8 % 95;
    out += char(32 + idx);
    delayMicroseconds(80);
  }

  randomSeed((unsigned long)adcAvg() ^ (unsigned long)micros());

  int replacements = min(3, STR_LEN);
  bool used[STR_LEN];
  for(int i=0; i<STR_LEN; i++) used[i] = false;

  int done = 0;
  while(done < replacements) {
    int pos = random(0, STR_LEN);
    if(used[pos]) continue;
    used[pos] = true;
    char c = char(32 + random(0, 95));
    out.setCharAt(pos, c);
    done++;
  }

  return out;
}


// ======================================================
// Cerca una stazione valida
// ======================================================
void tuneOneStation() {
  uint16_t f = rx.getRealFrequency();
  f += 10;

  if(f > 10800) f = 8750;

  rx.setFrequency(f);
  delay(200);

  while(true) {
    rx.seek(RDA_SEEK_WRAP, RDA_SEEK_UP);
    delay(500);

    uint16_t freq = rx.getRealFrequency();
    uint16_t rssi = rx.getRssi();
    uint16_t adc  = adcAvg();

    if(rssi > 12 && adc > 400){
      return;
    }
  }
}


// ======================================================
// Calcola SHA256
// ======================================================
String calcolaSHA256(String payload) {
  byte shaResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *)payload.c_str(), payload.length());
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);
  
  String hashStr = "";
  for (int i = 0; i < 32; i++) {
    char str[3];
    sprintf(str, "%02x", (int)shaResult[i]);
    hashStr += str;
  }
  return hashStr;
}


// ======================================================
// SETUP
// ======================================================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n=============================================");
  Serial.println("ESP32 + RDA5807 + AES-128 + Firebase Blockchain");
  Serial.println("=============================================\n");

  // WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connessione Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(300);
  }
  Serial.println(" OK!");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
  
  // NTP
  initNTP();
  
  // ======================================================
  // FIREBASE - Configurazione con Legacy Token (Database Secret)
  // ======================================================
  Serial.print("Configurazione Firebase... ");
  
  config.database_url = DATABASE_URL;
  config.signer.tokens.legacy_token = DATABASE_SECRET;
  
  Firebase.begin(&config, &auth);
  Firebase.reconnectWiFi(true);
  
  // Test connessione
  delay(1000);
  if (Firebase.ready()) {
    Serial.println("OK!");
  } else {
    Serial.println("In attesa...");
  }

  // I2C e Wire
  Wire.begin(SDA_PIN, SCL_PIN);

  // Pulsante
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(BUTTON_PIN), buttonISR, FALLING);
  Serial.println("Pulsante su GPIO " + String(BUTTON_PIN));

  // Radio
  rx.setup();
  rx.setBand(RDA_FM_BAND_USA_EU);
  rx.setMute(false);
  rx.setBass(true);
  rx.setVolume(15);
  rx.setFrequency(9000);
  delay(500);
  Serial.print("Volume: ");
  Serial.println(rx.getVolume());

  // ADC
  analogReadResolution(12);
  analogSetPinAttenuation(ADC_PIN, ADC_11db);
  pinMode(ADC_PIN, INPUT);

  // Prima stazione
  tuneOneStation();
  
  Serial.println("\n>>> PREMI IL PULSANTE PER GENERARE PASSWORD <<<\n");
}


// ======================================================
// LOOP
// ======================================================
void loop() {
  
  if(buttonPressed) {
    unsigned long currentTime = millis();
    
    if(currentTime - lastButtonTime > debounceDelay) {
      lastButtonTime = currentTime;
      
      uint16_t currentFreq = rx.getRealFrequency();
      uint16_t currentRssi = rx.getRssi();
      uint16_t currentAdc = adcAvg();
      
      String pwd = generatePassword();
      
      Serial.println("\n========================================");
      Serial.println(">>> PULSANTE PREMUTO <<<");
      Serial.print("Frequenza: ");
      Serial.print(currentFreq / 100.0, 2);
      Serial.println(" MHz");
      Serial.print("RSSI: ");
      Serial.println(currentRssi);
      Serial.print("ADC: ");
      Serial.println(currentAdc);
      Serial.print("PASSWORD: ");
      Serial.println(pwd);
      
      // Cifratura AES-128
      unsigned char encrypted[32];
      int encryptedLen = encryptAES128(pwd, encrypted);
      String timestamp = getTimestampString();
      
      Serial.println("----------------------------------------");
      Serial.print("PASSWORD CIFRATA (HEX): ");
      printHex(encrypted, encryptedLen);
      
      // ====== SALVATAGGIO FIREBASE ======
      Serial.println("----------------------------------------");
      Serial.println("Salvataggio su Firebase...");
      
      if (Firebase.ready()) {
        
        // 1. Leggi ultimo hash
        if (Firebase.RTDB.getString(&fbdo, percorsoMeta)) {
          if (fbdo.dataType() == "string" && fbdo.stringData().length() > 0) {
            ultimoHash = fbdo.stringData();
            Serial.println("Prev Hash: " + ultimoHash.substring(0, 16) + "...");
          }
        } else {
          Serial.println("Primo blocco (genesi)");
          ultimoHash = "0000000000000000000000000000000000000000000000000000000000000000";
        }
        
        // 2. Converti password cifrata in HEX string
        String passwordCifrata = "";
        for (int i = 0; i < encryptedLen; i++) {
          char hex[3];
          sprintf(hex, "%02X", encrypted[i]);
          passwordCifrata += hex;
        }
        
        // 3. Calcola nuovo hash
        String datiDaHashare = passwordCifrata + ultimoHash + timestamp;
        String nuovoHash = calcolaSHA256(datiDaHashare);
        Serial.println("Nuovo Hash: " + nuovoHash.substring(0, 16) + "...");
        
        // 4. Crea blocco JSON
        FirebaseJson json;
        json.set("timestamp", timestamp);
        json.set("data_cifrata", passwordCifrata);
        json.set("messaggio", "Password generata e salvata con successo");
        json.set("prev_hash", ultimoHash);
        json.set("curr_hash", nuovoHash);
        
        // 5. Salva blocco
        if (Firebase.RTDB.pushJSON(&fbdo, percorsoChain, &json)) {
          Serial.println("Blocco salvato: " + fbdo.pushName());
          
          // 6. Aggiorna ultimo hash
          if (Firebase.RTDB.setString(&fbdo, percorsoMeta, nuovoHash)) {
            Serial.println(">>> SUCCESSO! <<<");
          } else {
            Serial.println("Errore aggiornamento hash: " + fbdo.errorReason());
          }
        } else {
          Serial.println("Errore salvataggio: " + fbdo.errorReason());
        }
        
      } else {
        Serial.println("Firebase non pronto, riprova...");
      }
      
      Serial.println("========================================\n");
    }
    
    buttonPressed = false;
  }
  
  tuneOneStation();
}
