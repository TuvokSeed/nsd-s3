#include "nostr_event.h"

#include <ArduinoJson.h>
#include <Hash.h>

String nostrEventId(const String& json, const String& devicePubkey,
                    NostrEventInfo& info, uint8_t idOut[32]) {
  // `info` is a persistent, reused struct (one global instance across every
  // sign request) — reset the accumulator fields or a later event with no/
  // fewer "p" tags inherits stale counts from a previous, unrelated event.
  info.pTagCount = 0;
  info.firstPTag = "";

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, json);
  if (err) return "bad-json";

  if (!doc["created_at"].is<long long>()) return "missing-created_at";
  info.createdAt = doc["created_at"].as<long long>();

  if (!doc["kind"].is<int>()) return "missing-kind";
  info.kind = doc["kind"].as<int>();

  String pubkey = doc["pubkey"] | devicePubkey;
  pubkey.toLowerCase();
  if (pubkey.length() != 64) return "bad-pubkey";
  if (pubkey != devicePubkey) return "pubkey-mismatch";

  info.content = doc["content"] | "";

  if (!doc["tags"].isNull() && !doc["tags"].is<JsonArray>()) return "bad-tags";
  for (JsonArray t : doc["tags"].as<JsonArray>()) {
    if (t.size() >= 2 && t[0] == "p") {
      if (info.pTagCount == 0) info.firstPTag = t[1].as<String>();
      info.pTagCount++;
    }
  }

  // NIP-01: id = sha256(json array [0, pubkey, created_at, kind, tags, content])
  JsonDocument ser;
  JsonArray a = ser.to<JsonArray>();
  a.add(0);
  a.add(pubkey);
  a.add(info.createdAt);
  a.add(info.kind);
  if (doc["tags"].is<JsonArray>()) {
    a.add(doc["tags"]);
  } else {
    a.add<JsonArray>();
  }
  a.add(info.content);

  String serialized;
  serializeJson(ser, serialized);
  sha256((const uint8_t*)serialized.c_str(), serialized.length(), idOut);
  return "";
}

String nostrKindLabel(int kind) {
  switch (kind) {
    case 0: return "profile update";
    case 1: return "note";
    case 3: return "follow list";
    case 4: return "encrypted DM";
    case 5: return "delete request";
    case 6: return "repost";
    case 7: return "reaction";
    case 1059: return "gift wrap DM";
    case 9734: return "zap request";
    case 10002: return "relay list";
    case 22242: return "client auth";
    case 30023: return "article";
    default: return "kind " + String(kind);
  }
}
