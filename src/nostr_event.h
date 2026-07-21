#pragma once
#include <Arduino.h>

// Parsed summary of a Nostr event for the approval screen.
struct NostrEventInfo {
  int kind = -1;
  long long createdAt = 0;
  String content;
  String firstPTag;  // recipient hint for DMs / zaps ("" if none)
  int pTagCount = 0; // total "p" tags — a kind-3 follow list has many, not one recipient
};

// Parse `json`, fill `info`, and compute the NIP-01 event id into idOut[32].
// The id is computed on-device from the parsed fields — the client's own
// digest is never trusted. If the event has no `pubkey`, `devicePubkey` is
// used (the caller must then include it when assembling the signed event).
// Returns "" on success, otherwise a short error token.
String nostrEventId(const String& json, const String& devicePubkey,
                    NostrEventInfo& info, uint8_t idOut[32]);

// Human label for common kinds ("note", "DM", ... or "kind 12345").
String nostrKindLabel(int kind);
