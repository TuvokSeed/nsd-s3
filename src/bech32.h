// Minimal bech32 (BIP-173) encoder — enough for npub/nsec display.
#pragma once

#include <Arduino.h>

// Encodes `len` bytes with the given human-readable prefix, e.g.
// bech32Encode("npub", pubkey, 32) -> "npub1..."
String bech32Encode(const char* hrp, const uint8_t* data, size_t len);
