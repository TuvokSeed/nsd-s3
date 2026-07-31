// Private key storage in ESP32 NVS.
// v0.0.6: the vault stores the BIP-39 MNEMONIC (proper NIP-06: mnemonic ->
// BIP-32 HD-derive m/44'/1237'/0'/0/0 -> nsec), not the raw key -- the
// mnemonic is what "backup words" reveals, since a derived key can't be
// reversed back into the words that produced it. AES-256-GCM at rest, same
// PBKDF2-HMAC-SHA256(PIN) key-encryption-key as before.
// v0.0.5-and-earlier vaults (raw 32-byte key, no mnemonic behind it) are
// still readable so an existing key never gets bricked by this upgrade --
// keystoreUnlock() reports which kind it found. New vaults are always v2.
#pragma once

#include <Arduino.h>

bool keystoreHasVault();
bool keystoreHasLegacyKey();

// Encrypt an existing BIP-39 mnemonic (<=127 chars) under pin. Always
// creates a v2 (mnemonic) vault. Resets the fail counter.
bool keystoreCreateVault(const char* pin, const char* mnemonic);

// Legacy v1 creation path: encrypts a raw 32-byte key directly, no mnemonic.
// Used only by the v0.0.3-plaintext-key migration, where there is no
// mnemonic to store.
bool keystoreCreateVaultRawKey(const char* pin, const uint8_t key[32]);

// Decrypt the vault with pin.
//   returns 1: mnemonicOut filled (null-terminated, v2 vault)
//   returns 2: rawKeyOut[32] filled (legacy v1 vault, no mnemonic exists)
//   returns 0: wrong PIN, corrupt vault, or mnemonicOutLen too small
int keystoreUnlock(const char* pin, char* mnemonicOut, size_t mnemonicOutLen,
                    uint8_t rawKeyOut[32]);

bool keystoreLoadLegacy(uint8_t out[32]);
void keystoreDeleteLegacy();

// Wipes the entire NVS namespace (vault, legacy key, fail counter) -- the
// device's own in-firmware "factory reset". Distinct from a full chip erase
// (e.g. `pio run -t erase`): firmware stays intact, no reflash needed after.
void keystoreEraseAll();

// Fills out[16] with 128 bits of entropy for a 12-word mnemonic. v0.0.11:
// draws with the RF-independent hardware entropy source enabled (without it,
// esp_random() on a no-radio firmware is only pseudo-random) and mixes in the
// button-timing pool below.
void keystoreGenerateEntropy(uint8_t out[16]);

// Stir human interaction timing (e.g. button edges) into the entropy pool.
// Cheap (one SHA-256); call freely from input handling.
void keystoreEntropyStir(uint32_t event);

// True if k is nonzero and < the secp256k1 group order (a valid secret key).
bool keystoreIsValidSecret(const uint8_t k[32]);

// Consecutive wrong-PIN counter, persisted so a power cycle can't skip backoff.
uint32_t keystoreFailCount();
void keystoreSetFailCount(uint32_t n);
