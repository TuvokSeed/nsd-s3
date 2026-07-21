#include "keystore.h"

#include <Preferences.h>
#include <esp_random.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <string.h>

static const char* NVS_NS = "nsd";
static const char* NVS_LEGACY = "seckey";  // v0.0.3 plaintext key
static const char* NVS_VAULT = "vault";
static const char* NVS_FAILS = "fails";

// v1 (legacy, raw key) blob layout (81 bytes):
//   [0]      version = 1
//   [1..4]   PBKDF2 iterations, u32 LE
//   [5..20]  salt (16)
//   [21..32] GCM nonce (12)
//   [33..64] ciphertext = 32-byte raw secp256k1 key
//   [65..80] GCM tag (16)
#define VAULT1_LEN 81

// v2 (mnemonic) blob layout (177 bytes):
//   [0]       version = 2
//   [1..4]    PBKDF2 iterations, u32 LE
//   [5..20]   salt (16)
//   [21..32]  GCM nonce (12)
//   [33..160] ciphertext(128) = 1-byte length + up to 127 mnemonic chars,
//             zero-padded
//   [161..176] GCM tag (16)
#define VAULT2_LEN 177
#define MNEMONIC_MAX 127
#define KDF_ITERS 50000  // ~1s on the S3 with hw SHA; measure on hardware

// secp256k1 group order n
static const uint8_t CURVE_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
    0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

static bool isValidSecret(const uint8_t k[32]) {
  bool allZero = true;
  for (int i = 0; i < 32; i++) {
    if (k[i] != 0) allZero = false;
  }
  if (allZero) return false;
  for (int i = 0; i < 32; i++) {  // must be < n
    if (k[i] < CURVE_N[i]) return true;
    if (k[i] > CURVE_N[i]) return false;
  }
  return false;
}

static bool deriveKek(const char* pin, const uint8_t salt[16], uint32_t iters,
                      uint8_t kek[32]) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info || mbedtls_md_setup(&ctx, info, 1) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  int rc = mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char*)pin,
                                     strlen(pin), salt, 16, iters, 32, kek);
  mbedtls_md_free(&ctx);
  return rc == 0;
}

bool keystoreHasVault() {
  Preferences p;
  p.begin(NVS_NS, true);
  bool has = p.isKey(NVS_VAULT);
  p.end();
  return has;
}

bool keystoreHasLegacyKey() {
  Preferences p;
  p.begin(NVS_NS, true);
  bool has = p.isKey(NVS_LEGACY);
  p.end();
  return has;
}

bool keystoreCreateVaultRawKey(const char* pin, const uint8_t key[32]) {
  uint8_t blob[VAULT1_LEN];
  blob[0] = 1;
  uint32_t iters = KDF_ITERS;
  memcpy(blob + 1, &iters, 4);
  uint8_t* salt = blob + 5;
  uint8_t* nonce = blob + 21;
  uint8_t* ct = blob + 33;
  uint8_t* tag = blob + 65;
  esp_fill_random(salt, 16);
  esp_fill_random(nonce, 12);

  uint8_t kek[32];
  if (!deriveKek(pin, salt, iters, kek)) return false;

  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, kek, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, 32, nonce, 12,
                                   nullptr, 0, key, ct, 16, tag);
  }
  mbedtls_gcm_free(&g);
  memset(kek, 0, sizeof(kek));
  if (rc != 0) return false;

  Preferences p;
  p.begin(NVS_NS, false);
  size_t wrote = p.putBytes(NVS_VAULT, blob, VAULT1_LEN);
  p.putUInt(NVS_FAILS, 0);
  p.end();
  return wrote == VAULT1_LEN;
}

bool keystoreCreateVault(const char* pin, const char* mnemonic) {
  size_t mlen = strlen(mnemonic);
  if (mlen == 0 || mlen > MNEMONIC_MAX) return false;

  uint8_t plain[128];
  memset(plain, 0, sizeof(plain));
  plain[0] = (uint8_t)mlen;
  memcpy(plain + 1, mnemonic, mlen);

  uint8_t blob[VAULT2_LEN];
  blob[0] = 2;
  uint32_t iters = KDF_ITERS;
  memcpy(blob + 1, &iters, 4);
  uint8_t* salt = blob + 5;
  uint8_t* nonce = blob + 21;
  uint8_t* ct = blob + 33;
  uint8_t* tag = blob + 161;
  esp_fill_random(salt, 16);
  esp_fill_random(nonce, 12);

  uint8_t kek[32];
  if (!deriveKek(pin, salt, iters, kek)) {
    memset(plain, 0, sizeof(plain));
    return false;
  }

  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, kek, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, 128, nonce, 12,
                                   nullptr, 0, plain, ct, 16, tag);
  }
  mbedtls_gcm_free(&g);
  memset(kek, 0, sizeof(kek));
  memset(plain, 0, sizeof(plain));
  if (rc != 0) return false;

  Preferences p;
  p.begin(NVS_NS, false);
  size_t wrote = p.putBytes(NVS_VAULT, blob, VAULT2_LEN);
  p.putUInt(NVS_FAILS, 0);
  p.end();
  return wrote == VAULT2_LEN;
}

int keystoreUnlock(const char* pin, char* mnemonicOut, size_t mnemonicOutLen,
                    uint8_t rawKeyOut[32]) {
  uint8_t blob[VAULT2_LEN];  // large enough for either format
  Preferences p;
  p.begin(NVS_NS, true);
  size_t got = p.getBytes(NVS_VAULT, blob, sizeof(blob));
  p.end();

  if (got == VAULT1_LEN && blob[0] == 1) {
    uint32_t iters;
    memcpy(&iters, blob + 1, 4);
    uint8_t kek[32];
    if (!deriveKek(pin, blob + 5, iters, kek)) return 0;
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, kek, 256);
    if (rc == 0) {
      rc = mbedtls_gcm_auth_decrypt(&g, 32, blob + 21, 12, nullptr, 0,
                                    blob + 65, 16, blob + 33, rawKeyOut);
    }
    mbedtls_gcm_free(&g);
    memset(kek, 0, sizeof(kek));
    if (rc != 0) {
      memset(rawKeyOut, 0, 32);
      return 0;
    }
    return 2;
  }

  if (got == VAULT2_LEN && blob[0] == 2) {
    uint32_t iters;
    memcpy(&iters, blob + 1, 4);
    uint8_t kek[32];
    if (!deriveKek(pin, blob + 5, iters, kek)) return 0;
    uint8_t plain[128];
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, kek, 256);
    if (rc == 0) {
      rc = mbedtls_gcm_auth_decrypt(&g, 128, blob + 21, 12, nullptr, 0,
                                    blob + 161, 16, blob + 33, plain);
    }
    mbedtls_gcm_free(&g);
    memset(kek, 0, sizeof(kek));
    if (rc != 0) {
      memset(plain, 0, sizeof(plain));
      return 0;
    }
    uint8_t mlen = plain[0];
    if (mlen == 0 || mlen > MNEMONIC_MAX || (size_t)(mlen + 1) > mnemonicOutLen) {
      memset(plain, 0, sizeof(plain));
      return 0;
    }
    memcpy(mnemonicOut, plain + 1, mlen);
    mnemonicOut[mlen] = 0;
    memset(plain, 0, sizeof(plain));
    return 1;
  }

  return 0;
}

bool keystoreLoadLegacy(uint8_t out[32]) {
  Preferences p;
  p.begin(NVS_NS, true);
  size_t got = p.getBytes(NVS_LEGACY, out, 32);
  p.end();
  return got == 32;
}

void keystoreDeleteLegacy() {
  Preferences p;
  p.begin(NVS_NS, false);
  p.remove(NVS_LEGACY);
  p.end();
}

void keystoreEraseAll() {
  Preferences p;
  p.begin(NVS_NS, false);
  p.clear();
  p.end();
}

void keystoreGenerateEntropy(uint8_t out[16]) { esp_fill_random(out, 16); }

bool keystoreIsValidSecret(const uint8_t k[32]) { return isValidSecret(k); }

uint32_t keystoreFailCount() {
  Preferences p;
  p.begin(NVS_NS, true);
  uint32_t n = p.getUInt(NVS_FAILS, 0);
  p.end();
  return n;
}

void keystoreSetFailCount(uint32_t n) {
  Preferences p;
  p.begin(NVS_NS, false);
  p.putUInt(NVS_FAILS, n);
  p.end();
}
