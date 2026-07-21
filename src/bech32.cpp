#include "bech32.h"

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod(const uint8_t* values, size_t len) {
  static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                                  0x3d4233dd, 0x2a1462b3};
  uint32_t chk = 1;
  for (size_t i = 0; i < len; i++) {
    uint8_t top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (int j = 0; j < 5; j++) {
      if ((top >> j) & 1) chk ^= GEN[j];
    }
  }
  return chk;
}

String bech32Encode(const char* hrp, const uint8_t* data, size_t len) {
  size_t hrpLen = strlen(hrp);

  // 8-bit bytes -> 5-bit groups, padded
  uint8_t data5[(32 * 8 + 4) / 5 + 1];  // enough for 32-byte keys
  size_t d5len = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < len; i++) {
    acc = (acc << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data5[d5len++] = (acc >> bits) & 31;
    }
  }
  if (bits > 0) data5[d5len++] = (acc << (5 - bits)) & 31;

  // checksum over expanded hrp + data + 6 zero slots
  uint8_t values[2 * 16 + 1 + sizeof(data5) + 6];
  size_t vlen = 0;
  for (size_t i = 0; i < hrpLen; i++) values[vlen++] = hrp[i] >> 5;
  values[vlen++] = 0;
  for (size_t i = 0; i < hrpLen; i++) values[vlen++] = hrp[i] & 31;
  for (size_t i = 0; i < d5len; i++) values[vlen++] = data5[i];
  for (int i = 0; i < 6; i++) values[vlen++] = 0;
  uint32_t chk = polymod(values, vlen) ^ 1;

  String out = String(hrp) + "1";
  for (size_t i = 0; i < d5len; i++) out += CHARSET[data5[i]];
  for (int i = 0; i < 6; i++) out += CHARSET[(chk >> (5 * (5 - i))) & 31];
  return out;
}
