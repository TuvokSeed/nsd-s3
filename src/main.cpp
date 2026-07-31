// nostr-signer-s3 v0.0.10 — /shared-secret accepts an optional second token,
// a display-only "send"/"receive" hint from the host: the SHARE SECRET?
// screen now says "Sending message" / "Receiving message" instead of the
// generic "DM key exchange" when the caller provides it (flink.club does;
// lnbits horse and protocol-test.py don't, and still get the generic text).
// Purely cosmetic -- the hint carries no cryptographic weight and changes
// nothing about what gets approved. Prompted by v0.0.9 feedback: receiving
// a NIP-17 DM needs two separate approvals (the ephemeral outer wrap, then
// the sender's real-pubkey seal) and it wasn't obvious on-device which was
// which.
//
// nostr-signer-s3 v0.0.9 — /shared-secret now requires physical approval,
// same as signing. It used to answer instantly with no button press at all
// (a lnbits-horse-protocol accommodation: horse only waits 6s for a reply).
// That meant any host holding an open serial connection to an UNLOCKED
// device could silently pull the ECDH secret for any peer pubkey -- no
// screen prompt, nothing. Since NIP-17 DMs (flink.club) derive their NIP-44
// conversation key from this same primitive, that silent path could read or
// forge a user's private messages with zero on-device confirmation. Now
// routed through the same SIGN-screen state machine as /sign-message and
// /sign-event: an "SHARE SECRET?" screen shows the peer's pubkey prefix and
// requires ALLOW/DENY. Replies gain "busy" (another request already
// showing) / "rejected" (DENY) / "timeout" (60s elapsed unanswered), in
// addition to the existing 64-hex success reply. Tradeoff accepted
// knowingly: the lnbits horse extension's 6s wait will now generally time
// out unless answered fast, since it was built around the old silent
// behavior.
//
// nostr-signer-s3 v0.0.8 — in-firmware key erase, no flasher needed. The
// recover.flink.club "device already has a key" screen used to send people to
// flash.flink.club's full chip-erase option -- which also wipes the firmware,
// requiring a reflash before the device works again, and which can't be done
// from the same tab anyway (WebSerial ports are exclusive, so a second tab
// can't open a port the first tab is already holding). Now a new
// /erase-request command puts the device into an ERASE-CONFIRM screen
// (reachable only from MAIN or LOCKED, i.e. only when a key exists); a 3s
// physical HOLD on the device wipes just this app's NVS namespace (vault +
// fail-counter + any legacy remnant) and returns to NOKEY, all without ever
// touching the bootloader. Same physical-presence reasoning as v0.0.7's
// RESTORE hardening: a host should not be able to destroy an existing key
// the instant it connects.
//
// nostr-signer-s3 v0.0.7 — restore now requires physical presence on the
// device before /restore-words is accepted over serial. Previously a fresh
// device would derive a key from any 12 words sent over serial the moment it
// booted with no vault, with no on-device confirmation at all — a script on
// an untrusted host could silently provision the device the instant it was
// plugged in. The on-device 2048-word-per-slot scroll picker (the original,
// slower, fully air-gapped restore path) is removed in favor of this: it was
// superseded by the browser tool's scrambled on-screen keyboard + autocomplete,
// which is both faster and no longer requires typing raw digits/scrolling on
// the device itself. Now the NOKEY screen's RESTORE button arms a 5-minute
// window (Screen::RESTORE_WAIT) during which /restore-words is accepted;
// outside that window (or after it derives a key, or is cancelled) the serial
// command is refused with "error: not-armed". A new /restore-ready command
// lets a host poll whether the window is currently open.
//
// nostr-signer-s3 v0.0.6 — proper NIP-06: the vault now stores a 12-word
// BIP-39 mnemonic, and the signing key is BIP-32 HD-derived from it
// (m/44'/1237'/0'/0/0), same as any standard Nostr seed-phrase wallet. This
// replaces v0.0.5's raw-key word codec: that approach could only back up a
// key that already existed, but a derived key can never be reversed back
// into the words that produced it, so the mnemonic itself has to be what's
// stored and revealed. Verified the exact algorithm (BIP-39 seed + BIP-32
// CKDpriv) against the two official NIP-06 test vectors independently in
// Python before writing any device code; uBitcoin's HDPrivateKey class
// (vendors Trezor's own bip39/bip32 crypto) does the actual derivation here.
// v0.0.5-and-earlier vaults (raw key, no mnemonic behind it) still unlock
// fine — see keystore.h — just report "no backup words for this key" since
// there is, by construction, no mnemonic for them.
//
// Key material is AES-256-GCM encrypted at rest under a PIN-derived key (see
// keystore.h), never leaves the device, and signing requires a physical
// button press.
//
// Lock model: boot starts LOCKED (6-digit PIN, digit picker: BOTTOM cycles 0-9,
// TOP confirms). Wrong PINs get exponential backoff (2s..60s, counter persisted
// across power cycles); the key is NEVER wiped by failed attempts. Unlock lasts
// until power-off (user decision 2026-07-15: no idle auto-lock — the board is
// USB-powered, so unplugging IS the lock). While locked, key-using serial
// commands answer "error: locked" (/sign-message answers "Rejected" for LNbits
// horse compat); /ping and /version still work. v0.0.3 plaintext keys are
// migrated on first boot: set a PIN, key is re-stored encrypted (as a legacy
// raw-key vault — there was never a mnemonic for those either).
//
// UI convention: in landscape the two buttons sit on the RIGHT edge of the screen
// (top = GPIO14 "KEY", bottom = GPIO0 "BOOT"). All screens label actions with
// edge-anchored tags next to the physical button, never with PCB names.
//
// Serial protocol (newline-terminated, replies framed as "/method <data>" so the
// lnbits horse / nos2x-nsd extensions can parse them):
//
//   LNbits-NSD compatible:
//   /ping                  -> (no reply)            [flushes the line buffer]
//   /ping <host>           -> /ping 0 <device-id>   [host shown on display]
//   /public-key            -> /public-key <64hex x-only>
//   /sign-message <64hex>  -> approval screen ->
//                             /sign-message <128hex sig> | /sign-message Rejected
//   /shared-secret <peer> [send|receive]  -> approval screen ("SHARE SECRET?",
//                             showing "Sending"/"Receiving message" if a
//                             purpose hint was given, else generic text) ->
//                             /shared-secret <64hex ecdh-x>   (NIP-04)
//                             | /shared-secret rejected | timeout | busy
//                             peer = 128hex X||Y (horse), 66hex compressed, or 64hex x-only
//
//   Extensions (nostr-signer-s3 only, used by flink.club and our tools):
//   /sign-event <json>     -> event-aware approval screen; id computed ON DEVICE
//                             (client digest never trusted) ->
//                             /sign-event <64hex id> <128hex sig>
//                             | /sign-event rejected | /sign-event timeout
//                             | /sign-event error <token>
//   /erase-request         -> /erase-request ok | error: no-key | error: busy
//                             only valid on MAIN or LOCKED (a key must
//                             exist); puts the device into an ERASE-CONFIRM
//                             screen requiring a 3s physical HOLD to actually
//                             wipe -- wipes the NVS vault only, NOT a full
//                             chip erase (firmware stays intact, no reflash
//                             needed after); CANCEL on that screen aborts
//   /version               -> /version nostr-signer-s3 v0.0.8
//   /npub                  -> /npub npub1...
//   /last-button           -> /last-button <which>  (debug)
//   /restore-ready         -> /restore-ready armed | not-armed | error: key-exists
//                             poll this after connecting; "armed" only while
//                             the device is showing its RESTORE-WAIT screen
//                             (user tapped RESTORE on a fresh device, 5 min window)
//   /restore-words w1..w12 -> /restore-words ok | error <reason>
//                             fresh-device only AND only while armed (see
//                             /restore-ready above) -- replies "error: not-armed"
//                             otherwise, even on an otherwise-fresh device;
//                             standard BIP-39 checksum validated via
//                             checkMnemonic(); PIN is still entered on-device
//   /selftest-nip06        -> /selftest-nip06 <64hex pubkey> <npub>
//                             TEMPORARY diagnostic: derives from the fixed
//                             official NIP-06 test mnemonic in RAM only (no
//                             vault/state touched at all) so the derivation
//                             path can be checked against the published test
//                             vector without risking any real key. Remove
//                             once no longer needed.

#include <Arduino.h>
#include <Bitcoin.h>

#include "LGFX_TDisplayS3.hpp"
#include "bech32.h"
#include "keystore.h"
#include "nostr_event.h"
#include "qrcode.h"

#define FW_VERSION "0.0.11"
#define SIGN_TIMEOUT_MS 60000
#define GENERATE_HOLD_MS 3000
#define RX_MAX 8192
#define PIN_LEN 6
#define BACKOFF_CAP_MS 60000
#define RESTORE_ARM_MS (5 * 60 * 1000UL)  // window /restore-words stays accepted
#define MNEMONIC_WORDS 12

static LGFX_TDisplayS3 tft;

struct Button {
  explicit Button(uint8_t p) : pin(p) {}
  uint8_t pin;
  bool pressed = false;
  bool changed = false;
  uint32_t lastEdgeMs = 0;

  void poll() {
    bool raw = digitalRead(pin) == LOW;
    changed = false;
    if (raw != pressed && millis() - lastEdgeMs > 30) {  // debounce
      pressed = raw;
      changed = true;
      lastEdgeMs = millis();
      keystoreEntropyStir(((uint32_t)pin << 1) | (raw ? 1 : 0));
    }
  }
  bool tapped() { return changed && pressed; }
};

// physical position in landscape orientation (verified on hardware 2026-07-14)
static Button btnTop(PIN_BTN_KEY);     // GPIO14, upper right
static Button btnBottom(PIN_BTN_BOOT); // GPIO0, lower right

enum class Screen { NOKEY, MAIN, QR, SIGN, LOCKED, SETPIN, BACKUP_WARN, BACKUP_SHOW, RESTORE_WAIT, ERASE_CONFIRM };
static Screen screen = Screen::NOKEY;

static uint8_t secKey[32];
static bool haveKey = false;  // true = unlocked, key material in RAM
static String pubHex;  // x-only, 64 hex chars
static String npub;
static String pairedHost;  // from "/ping <host>", shown on MAIN

// The mnemonic behind the currently-unlocked key, if any. Empty for a
// legacy (pre-v0.0.6) raw-key vault, which has no mnemonic to show.
static String curMnemonic;

// PIN entry state (LOCKED and SETPIN screens share the digit picker)
static char pinBuf[PIN_LEN + 1];
static uint8_t pinPos = 0;
static uint8_t curDigit = 0;
static char firstPin[PIN_LEN + 1];  // SETPIN phase 0 result, for confirm
static uint8_t setupPhase = 0;      // 0 = choose PIN, 1 = confirm PIN
static uint8_t pendingKey[32];      // legacy-migration raw key, awaiting vault
static String pendingMnemonic;      // new-vault mnemonic, awaiting vault creation
static bool setupIsLegacyMigration = false;
static bool setupFromGenerate = false;  // fresh key -> show QR after setup
static uint32_t backoffUntil = 0;

// pending sign job (digest-based, event-based, or shared-secret)
static uint8_t signDigest[32];
static String signReplyCmd;      // "/sign-message", "/sign-event", or "/shared-secret"
static String signRejectReply;   // reply data on reject (protocol-dependent)
static String signTimeoutReply;  // reply data on timeout
static bool signIsEvent = false;
static bool signIsSecret = false;
static NostrEventInfo signEvent;
static uint8_t pendingPeerSec[33];  // /shared-secret: peer's SEC-compressed pubkey, awaiting approval
static String signSecretPurpose;    // /shared-secret: optional "send"/"receive" hint, display only
static uint32_t signRequestedAt = 0;
static String lastButton = "none";

// backup-words reveal (the mnemonic behind the current key, on-device only,
// never serial)
static uint8_t backupPage = 0;
static String backupWords[MNEMONIC_WORDS];

// restore-from-words: RESTORE on the NOKEY screen arms a window during which
// /restore-words is accepted over serial; the words themselves are typed on
// the host (recover.flink.club's scrambled on-screen keyboard), not the device.
static bool restoreArmed = false;
static uint32_t restoreArmedUntil = 0;

// ---------- key handling ----------

static void derivePublic() {
  PrivateKey pk(secKey);
  // toString() gives the 33-byte compressed SEC hex; x-only = drop the parity byte
  pubHex = pk.publicKey().toString().substring(2);
  uint8_t pubBytes[32];
  fromHex(pubHex, pubBytes, 32);
  npub = bech32Encode("npub", pubBytes, 32);
}

// Fixed-position bar for the two genuinely slow operations (PIN unlock,
// key derivation) -- drawn between real completed steps, not on a timer.
static void drawProgressBar(int step, int total) {
  const int barX = 10, barY = 156, barW = 230, barH = 10;
  tft.drawRect(barX, barY, barW, barH, TFT_DARKGREY);
  tft.fillRect(barX + 1, barY + 1, barW - 2, barH - 2, TFT_BLACK);
  int fillW = (barW - 2) * step / total;
  if (fillW > 0) tft.fillRect(barX + 1, barY + 1, fillW, barH - 2, TFT_GREEN);
}

// NIP-06: mnemonic -> BIP-32 seed -> HD-derive m/44'/1237'/0'/0/0 -> nsec.
// No passphrase (empty string, standard default). Returns false only if the
// derived scalar is somehow out of secp256k1 range (astronomically unlikely).
//
// The path is walked one child() at a time (rather than one derive(path)
// call) so a delay(1) can be inserted between each step -- this whole
// operation is genuinely slow (~7s: 2048-round seed PBKDF2 + two full EC
// point multiplications for the non-hardened levels), and run as a single
// blocking call it never yields back to FreeRTOS, which trips the task
// watchdog and reboots the device mid-derivation (confirmed: caused a real
// USB disconnect while debugging this). delay(1) at each boundary resets the
// watchdog; the progress bar is a side benefit of already having the steps
// broken out.
static bool deriveFromMnemonic(const String& mnemonic, uint8_t secretOut[32],
                                bool showProgress = false) {
  if (showProgress) {
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(10, 140);
    tft.print("deriving key...");
    drawProgressBar(0, 6);
  }
  delay(1);
  HDPrivateKey hd(mnemonic, String(""), &Mainnet, nullptr);  // seed PBKDF2
  if (showProgress) drawProgressBar(1, 6);
  delay(1);
  HDPrivateKey k = hd.child(44 + HARDENED_INDEX);
  if (showProgress) drawProgressBar(2, 6);
  delay(1);
  k = k.child(1237 + HARDENED_INDEX);
  if (showProgress) drawProgressBar(3, 6);
  delay(1);
  k = k.child(HARDENED_INDEX);  // account 0'
  if (showProgress) drawProgressBar(4, 6);
  delay(1);
  k = k.child(0);  // change (non-hardened: EC point mult)
  if (showProgress) drawProgressBar(5, 6);
  delay(1);
  k = k.child(0);  // index (non-hardened: EC point mult)
  if (showProgress) drawProgressBar(6, 6);
  delay(1);
  k.getSecret(secretOut);
  return keystoreIsValidSecret(secretOut);
}

// ---------- serial helpers ----------

static void reply(const char* method, const String& data) {
  Serial.printf("%s %s\n", method, data.c_str());
}

static String deviceId() {
  uint64_t mac = ESP.getEfuseMac();
  char buf[13];
  snprintf(buf, sizeof(buf), "%012llx", mac);
  return String("nsd-s3-") + buf;
}

// ---------- drawing helpers ----------

// Tag anchored to the right edge, vertically next to the physical button it maps to.
static void drawEdgeLabel(bool top, const char* text, uint16_t color, uint16_t bg) {
  tft.setTextSize(2);
  tft.setTextColor(color, bg);
  int w = strlen(text) * 12;
  tft.setCursor(tft.width() - w - 4, top ? 6 : tft.height() - 22);
  tft.print(text);
}

static void drawHeader(const char* subtitle) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(3);
  tft.setTextColor(TFT_MAGENTA, TFT_BLACK);
  tft.setCursor(10, 10);
  tft.print("NSD-S3");
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(130, 18);
  tft.print(subtitle);
  tft.drawFastHLine(0, 48, tft.width(), TFT_DARKGREY);
}

// Content preview: printable ASCII only, newlines to spaces, one '?' per
// non-ASCII sequence (the built-in font cannot draw UTF-8).
static String sanitizePreview(const String& s, unsigned int maxLen) {
  String out;
  for (unsigned int i = 0; i < s.length() && out.length() < maxLen; i++) {
    uint8_t c = s[i];
    if (c >= 0x20 && c < 0x7f) {
      out += (char)c;
    } else if (c == '\n' || c == '\r' || c == '\t') {
      out += ' ';
    } else if (c >= 0xc0) {  // UTF-8 lead byte
      out += '?';
    }  // skip UTF-8 continuation bytes and other control chars
  }
  if (out.length() >= maxLen) out += "...";
  return out;
}

// ---------- screens ----------

// The 3-second hold has no feedback otherwise -- pressing and letting go
// early (or wondering if it's registering at all) looks identical to it
// just not working. This line doubles as the idle instruction and, while
// held, a live countdown.
static void drawNoKeyHoldLine() {
  if (btnTop.pressed) {
    uint32_t held = millis() - btnTop.lastEdgeMs;
    uint32_t remain = (held >= GENERATE_HOLD_MS)
                          ? 0
                          : (GENERATE_HOLD_MS - held + 999) / 1000;
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setCursor(10, 100);
    tft.printf("Holding... keep %lus ", (unsigned long)remain);
  } else {
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(10, 100);
    tft.print("Hold NEW KEY 3 sec  ");
  }
}

static void showNoKey() {
  screen = Screen::NOKEY;
  drawHeader("v" FW_VERSION);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setCursor(10, 65);
  tft.print("No key on device");
  drawNoKeyHoldLine();
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 122);
  tft.print("or RESTORE at:");
  // Smaller font for the domain: at size 2 "recover.flink.club" is wide
  // enough (19 chars) to run under the RESTORE edge label's bottom-right
  // corner (label starts at x=width-108-4=208, y=height-22=148) -- at size 1
  // it comfortably clears both.
  tft.setTextSize(1);
  tft.setCursor(10, 136);
  tft.print("recover.flink.club");
  tft.setTextSize(2);  // ambient size restored: drawNoKeyHoldLine() redraws
                        // itself later from loop() without setting its own
  drawEdgeLabel(true, "NEW KEY >", TFT_GREEN, TFT_BLACK);
  drawEdgeLabel(false, "RESTORE >", TFT_CYAN, TFT_BLACK);
}

static void showMain() {
  screen = Screen::MAIN;
  drawHeader("v" FW_VERSION);
  // full npub in 4 lines of 16 chars, right column stays free for button tags
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  for (int i = 0; i < 4; i++) {
    tft.setCursor(10, 58 + i * 20);
    tft.print(npub.substring(i * 16, min((i + 1) * 16, (int)npub.length())));
  }
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 148);
  if (pairedHost.length()) {
    tft.print(sanitizePreview(pairedHost, 22));
  } else {
    tft.print("your npub");
  }
  drawEdgeLabel(true, "BACKUP >", TFT_CYAN, TFT_BLACK);
  drawEdgeLabel(false, "QR >", TFT_WHITE, TFT_BLACK);
}

static void showQr() {
  screen = Screen::QR;
  QRCode qr;
  uint8_t qrData[qrcode_getBufferSize(5)];
  qrcode_initText(&qr, qrData, 5, ECC_MEDIUM, npub.c_str());

  const int scale = 4;
  const int px = qr.size * scale;  // 37*4 = 148
  const int x0 = (tft.width() - px) / 2;
  const int y0 = (tft.height() - px) / 2;

  tft.fillScreen(TFT_WHITE);
  for (uint8_t y = 0; y < qr.size; y++) {
    for (uint8_t x = 0; x < qr.size; x++) {
      if (qrcode_getModule(&qr, x, y)) {
        tft.fillRect(x0 + x * scale, y0 + y * scale, scale, scale, TFT_BLACK);
      }
    }
  }
  tft.setTextSize(1);
  tft.setTextColor(TFT_BLACK, TFT_WHITE);
  tft.setCursor(4, tft.height() - 10);
  tft.print("npub QR");
  drawEdgeLabel(false, "BACK >", TFT_BLACK, TFT_WHITE);
}

static void showSetPin(const char* status, uint16_t color);  // defined below
static bool isLocked();                                      // defined below
static void showLocked(const char* status, uint16_t color);  // defined below
static void resetPinEntry();                                 // defined below

// ---------- backup words (reveal the mnemonic behind the current key) ----------

// Same hold-to-confirm pattern as NEW KEY on the NOKEY screen -- a plain tap
// was too easy to trigger by accident for something this sensitive.
static void drawBackupShowHoldLine() {
  if (btnTop.pressed) {
    uint32_t held = millis() - btnTop.lastEdgeMs;
    uint32_t remain = (held >= GENERATE_HOLD_MS)
                          ? 0
                          : (GENERATE_HOLD_MS - held + 999) / 1000;
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setCursor(10, 134);
    tft.printf("Hold... %lus  ", (unsigned long)remain);
  } else {
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(10, 134);
    tft.print("Hold SHOW 3 sec     ");
  }
}

static void showBackupWarn() {
  screen = Screen::BACKUP_WARN;
  drawHeader("BACKUP");
  tft.setTextColor(TFT_ORANGE, TFT_BLACK);
  tft.setCursor(10, 60);
  tft.print("Show 12 backup words?");
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 90);
  tft.print("Anyone who sees them");
  tft.setCursor(10, 112);
  tft.print("can steal your key.");
  drawBackupShowHoldLine();
  drawEdgeLabel(true, "HOLD SHOW >", TFT_GREEN, TFT_BLACK);
  drawEdgeLabel(false, "CANCEL >", TFT_RED, TFT_BLACK);
}

static void drawBackupPage() {
  drawHeader("WORDS");
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setCursor(10, 58);
  tft.printf("Page %d / 3", backupPage + 1);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  for (int i = 0; i < 4; i++) {
    int n = backupPage * 4 + i;
    tft.setCursor(10, 80 + i * 20);
    tft.printf("%2d. %s", n + 1, backupWords[n].c_str());
  }
  drawEdgeLabel(true, "DONE >", TFT_GREEN, TFT_BLACK);
  drawEdgeLabel(false, "NEXT >", TFT_WHITE, TFT_BLACK);
}

static void showBackupPage() {
  screen = Screen::BACKUP_SHOW;
  backupPage = 0;
  int n = 0;
  String rest = curMnemonic;
  while (rest.length() && n < MNEMONIC_WORDS) {
    int sp = rest.indexOf(' ');
    backupWords[n] = (sp < 0) ? rest : rest.substring(0, sp);
    rest = (sp < 0) ? "" : rest.substring(sp + 1);
    n++;
  }
  drawBackupPage();
}

// ---------- restore-arm (fresh device only; words are typed on the host) ----------

// Live countdown of the arm window, redrawn only when the displayed second
// changes -- same pattern as drawBackoff().
// y=130: clear of the "recover.flink.club" line above it (ends y=124) and
// of the CANCEL edge label below (starts y=148) -- same overlap class as
// the NOKEY screen's RESTORE label sitting over its domain text.
static void drawRestoreWaitCountdown() {
  static uint32_t lastShown = 0xffffffff;
  uint32_t left = (restoreArmedUntil - millis() + 999) / 1000;
  if (left == lastShown) return;
  lastShown = left;
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 130);
  tft.printf("expires in %lus   ", (unsigned long)left);
}

static void drawRestoreWait() {
  drawHeader("RESTORE");
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.setCursor(10, 60);
  tft.print("Enter your 12 words");
  tft.setCursor(10, 82);
  tft.print("on your PC now:");
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 108);
  tft.print("recover.flink.club");
  drawEdgeLabel(false, "CANCEL >", TFT_RED, TFT_BLACK);
}

// Tapping RESTORE on the NOKEY screen opens a time-boxed window during which
// /restore-words is accepted over serial -- physical presence at the device
// is required before a host can ever provision it, so a script running on an
// untrusted PC can't silently restore a key the moment a fresh device is
// plugged in.
static void armRestore() {
  screen = Screen::RESTORE_WAIT;
  restoreArmed = true;
  restoreArmedUntil = millis() + RESTORE_ARM_MS;
  drawRestoreWait();
  drawRestoreWaitCountdown();
}

static void disarmRestore() {
  restoreArmed = false;
  showNoKey();
}

static void handleRestoreWaitInput() {
  if (btnBottom.tapped() || millis() >= restoreArmedUntil) {
    disarmRestore();
    return;
  }
  drawRestoreWaitCountdown();
}

// ---------- erase (wipe the current key, in-firmware -- no flasher) ----------

// Same hold-to-confirm pattern as NEW KEY / BACKUP SHOW -- this is at least
// as destructive as either, so it gets the same 3s deliberateness gate.
static void drawEraseHoldLine() {
  if (btnTop.pressed) {
    uint32_t held = millis() - btnTop.lastEdgeMs;
    uint32_t remain = (held >= GENERATE_HOLD_MS)
                          ? 0
                          : (GENERATE_HOLD_MS - held + 999) / 1000;
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setCursor(10, 134);
    tft.printf("Hold... %lus  ", (unsigned long)remain);
  } else {
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(10, 134);
    tft.print("Hold ERASE 3 sec    ");
  }
}

static void showEraseConfirm() {
  screen = Screen::ERASE_CONFIRM;
  drawHeader("ERASE?");
  tft.setTextColor(TFT_ORANGE, TFT_BLACK);
  tft.setCursor(10, 60);
  tft.print("Wipe this key?");
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 90);
  tft.print("Cannot be undone");
  tft.setCursor(10, 112);
  tft.print("unless backed up.");
  drawEraseHoldLine();
  drawEdgeLabel(true, "HOLD ERASE >", TFT_GREEN, TFT_BLACK);
  drawEdgeLabel(false, "CANCEL >", TFT_RED, TFT_BLACK);
}

// Wipes the whole NVS namespace (vault + fail-counter + any legacy remnant)
// and returns to NOKEY -- an in-firmware factory reset, not a chip erase.
static void performErase() {
  keystoreEraseAll();
  memset(secKey, 0, sizeof(secKey));
  haveKey = false;
  pubHex = "";
  npub = "";
  curMnemonic = "";
  pairedHost = "";
  backoffUntil = 0;
  resetPinEntry();
  showNoKey();
}

// Cancel returns to wherever erase was requested from -- recomputed from
// current vault state rather than stored, since only MAIN/LOCKED can ever
// reach this screen.
static void cancelEraseConfirm() {
  if (isLocked()) {
    showLocked("Enter PIN", TFT_LIGHTGREY);
  } else {
    showMain();
  }
}

static void showSignRequest() {
  screen = Screen::SIGN;
  signRequestedAt = millis();

  if (signIsSecret) {
    // ECDH shared-secret derivation (NIP-04 encryption, and NIP-44's
    // conversation-key derivation for NIP-17 DMs) used to answer instantly
    // with no button press at all -- silent by design, to fit inside the
    // lnbits horse extension's 6s reply window. That is exactly the kind of
    // silent key operation this device should never allow: a host with an
    // open, unlocked serial connection could otherwise pull the DM secret
    // for any peer with zero on-screen confirmation. Now gated identically
    // to signing -- horse's 6s window will generally time out unless
    // answered fast, which is an accepted tradeoff, not a bug.
    // drawHeader's subtitle is fixed at x=130 regardless of length -- every
    // other header ("SIGN?", "LOCKED", etc.) is short enough to clear the
    // top-right edge label's x-band, but "SHARE SECRET?" (13 chars) ran
    // straight into "ALLOW >". Shortened to match the existing pattern; the
    // fuller "Sending/Receiving message" text is already one line below.
    drawHeader("SHARE?");
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(10, 58);
    // purpose is a display-only hint the host supplies (not part of the
    // crypto) -- lets flink.club distinguish "sending" from "receiving" on
    // screen instead of the generic label; unrecognized/absent falls back
    // to the old wording, so lnbits horse and protocol-test.py (which never
    // send a purpose token) still show something sensible.
    if (signSecretPurpose == "send") {
      tft.print("Sending message");
    } else if (signSecretPurpose == "receive") {
      tft.print("Receiving message");
    } else {
      tft.print("DM key exchange");
    }
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(10, 80);
    tft.print("peer:");
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(10, 102);
    tft.print(toHex(pendingPeerSec + 1, 32).substring(0, 16) + "...");
    drawEdgeLabel(true, "ALLOW >", TFT_GREEN, TFT_BLACK);
    drawEdgeLabel(false, "DENY >", TFT_RED, TFT_BLACK);
    return;
  }

  drawHeader("SIGN?");
  if (signIsEvent) {
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(10, 58);
    tft.print(nostrKindLabel(signEvent.kind));
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(10, 80);
    if (signEvent.kind == 3) {
      // a follow list's "p" tags are the followed pubkeys, not a single
      // recipient — "to <first pubkey>..." would misleadingly read like a DM
      tft.print(String(signEvent.pTagCount) + (signEvent.pTagCount == 1 ? " follow" : " follows"));
    } else if (signEvent.firstPTag.length() == 64) {
      tft.print("to " + signEvent.firstPTag.substring(0, 12) + "...");
    }
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    String preview = sanitizePreview(signEvent.content, 48);  // 3 lines x 16
    if (preview.isEmpty()) {
      tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
      preview = "(no text content)";
    }
    for (int i = 0; i < 3 && (int)preview.length() > i * 16; i++) {
      tft.setCursor(10, 102 + i * 20);
      tft.print(preview.substring(i * 16, min((i + 1) * 16, (int)preview.length())));
    }
  } else {
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(10, 58);
    tft.print("External request");
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    String digestHex = toHex(signDigest, 32);
    for (int i = 0; i < 4; i++) {  // 4 lines x 16 chars, right column free
      tft.setCursor(10, 80 + i * 20);
      tft.print(digestHex.substring(i * 16, (i + 1) * 16));
    }
  }
  drawEdgeLabel(true, "SIGN >", TFT_GREEN, TFT_BLACK);
  drawEdgeLabel(false, "REJECT >", TFT_RED, TFT_BLACK);
}

// ---------- PIN lock ----------

static bool isLocked() { return keystoreHasVault() && !haveKey; }

static void resetPinEntry() {
  memset(pinBuf, 0, sizeof(pinBuf));
  pinPos = 0;
  curDigit = 0;
}

// Six slots: entered digits masked '*', current position shows the live digit,
// remaining positions '_'. Right column stays free for the button tags.
static void drawPinSlots() {
  tft.setTextSize(3);
  for (int i = 0; i < PIN_LEN; i++) {
    tft.setCursor(14 + i * 30, 92);
    if (i < pinPos) {
      tft.setTextColor(TFT_WHITE, TFT_BLACK);
      tft.print('*');
    } else if (i == pinPos) {
      tft.setTextColor(TFT_YELLOW, TFT_BLACK);
      tft.print((char)('0' + curDigit));
    } else {
      tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
      tft.print('_');
    }
  }
  tft.setTextSize(2);
}

static void drawPinScreen(const char* title, const char* status,
                          uint16_t statusColor) {
  drawHeader(title);
  tft.setTextColor(statusColor, TFT_BLACK);
  tft.setCursor(10, 58);
  tft.print(status);
  drawPinSlots();
  drawEdgeLabel(true, "OK >", TFT_GREEN, TFT_BLACK);
  drawEdgeLabel(false, "0-9 >", TFT_WHITE, TFT_BLACK);
}

static void showLocked(const char* status, uint16_t color) {
  screen = Screen::LOCKED;
  resetPinEntry();
  drawPinScreen("LOCKED", status, color);
}

static void showSetPin(const char* status, uint16_t color) {
  screen = Screen::SETPIN;
  resetPinEntry();
  drawPinScreen(setupPhase == 0 ? "SET PIN" : "CONFIRM", status, color);
}

// A sign/secret request arrived while locked: tell the user why nothing happened.
static void drawLockedHint() {
  if (screen != Screen::LOCKED) return;
  tft.setTextColor(TFT_ORANGE, TFT_BLACK);
  tft.setCursor(10, 140);
  tft.print("denied - unlock");  // keep short: bottom edge tag starts at x=256
}

// Backoff countdown line, redrawn at most once a second while it runs.
static void drawBackoff() {
  static uint32_t lastShown = 0;
  uint32_t left = (backoffUntil - millis() + 999) / 1000;
  if (left == lastShown) return;
  lastShown = left;
  tft.setTextColor(TFT_ORANGE, TFT_BLACK);
  tft.setCursor(10, 140);
  tft.printf("wait %lus  ", (unsigned long)left);
}

static void startBackoff() {
  uint32_t fails = keystoreFailCount();
  if (fails == 0) return;
  uint32_t ms = 1000UL << min(fails, (uint32_t)6);  // 2s,4s,...,64s
  backoffUntil = millis() + min(ms, (uint32_t)BACKOFF_CAP_MS);
}

static void tryUnlock() {
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 140);
  tft.print("checking...");
  char mnemonicBuf[128];
  uint8_t rawKey[32];
  int kind = keystoreUnlock(pinBuf, mnemonicBuf, sizeof(mnemonicBuf), rawKey);
  if (kind == 1) {
    memset(pinBuf, 0, sizeof(pinBuf));
    keystoreSetFailCount(0);
    curMnemonic = String(mnemonicBuf);
    memset(mnemonicBuf, 0, sizeof(mnemonicBuf));
    if (!deriveFromMnemonic(curMnemonic, secKey, true)) {  // next-to-impossible
      haveKey = false;
      showLocked("Derive failed, retry", TFT_RED);
      return;
    }
    haveKey = true;
    derivePublic();
    showMain();
  } else if (kind == 2) {
    memset(pinBuf, 0, sizeof(pinBuf));
    keystoreSetFailCount(0);
    memcpy(secKey, rawKey, 32);
    memset(rawKey, 0, sizeof(rawKey));
    curMnemonic = "";  // legacy vault: no mnemonic backs this key
    haveKey = true;
    derivePublic();
    showMain();
  } else {
    memset(pinBuf, 0, sizeof(pinBuf));
    keystoreSetFailCount(keystoreFailCount() + 1);
    startBackoff();
    showLocked("Wrong PIN", TFT_RED);
  }
}

// SETPIN: phase 0 stores the chosen PIN, phase 1 confirms it, then either the
// pending mnemonic (new-style vault) or the legacy raw key (v0.0.3 migration
// only) is sealed into the vault.
static void finishPinPhase() {
  if (setupPhase == 0) {
    memcpy(firstPin, pinBuf, sizeof(firstPin));
    setupPhase = 1;
    showSetPin("Repeat your PIN", TFT_LIGHTGREY);
    return;
  }
  if (memcmp(firstPin, pinBuf, PIN_LEN) != 0) {
    memset(firstPin, 0, sizeof(firstPin));
    setupPhase = 0;
    showSetPin("PINs differ, retry", TFT_RED);
    return;
  }
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(10, 140);
  tft.print("encrypting...");
  bool ok = setupIsLegacyMigration
                ? keystoreCreateVaultRawKey(pinBuf, pendingKey)
                : keystoreCreateVault(pinBuf, pendingMnemonic.c_str());
  memset(firstPin, 0, sizeof(firstPin));
  memset(pinBuf, 0, sizeof(pinBuf));
  if (!ok) {  // RNG/NVS failure — keep the pending material, let the user retry
    setupPhase = 0;
    showSetPin("Store failed, retry", TFT_RED);
    return;
  }
  keystoreDeleteLegacy();
  if (setupIsLegacyMigration) {
    memcpy(secKey, pendingKey, 32);
    curMnemonic = "";
  } else {
    curMnemonic = pendingMnemonic;
    deriveFromMnemonic(curMnemonic, secKey, true);  // validated already at restore/generate time
  }
  memset(pendingKey, 0, sizeof(pendingKey));
  pendingMnemonic = "";
  haveKey = true;
  derivePublic();
  Serial.println(setupFromGenerate ? "key-generated" : "key-migrated");
  if (setupFromGenerate) {
    setupFromGenerate = false;
    showQr();
  } else {
    showMain();
  }
}

// Shared digit-picker input for LOCKED and SETPIN.
static void handlePinInput() {
  if (btnBottom.tapped()) {
    curDigit = (curDigit + 1) % 10;
    drawPinSlots();
  }
  if (btnTop.tapped()) {
    pinBuf[pinPos++] = '0' + curDigit;
    curDigit = 0;
    if (pinPos == PIN_LEN) {
      pinBuf[PIN_LEN] = '\0';
      if (screen == Screen::LOCKED) {
        tryUnlock();
      } else {
        finishPinPhase();
      }
    } else {
      drawPinSlots();
    }
  }
}

// ---------- signing ----------

static void finishSign(bool approved) {
  if (signIsSecret) {
    if (approved) {
      PublicKey peer(pendingPeerSec);
      PrivateKey pk(secKey);
      uint8_t secret[32];
      pk.ecdh(peer, secret, false);
      reply(signReplyCmd.c_str(), toHex(secret, 32));
      memset(secret, 0, 32);
    } else {
      reply(signReplyCmd.c_str(), signRejectReply);
    }
    memset(pendingPeerSec, 0, sizeof(pendingPeerSec));
    signIsSecret = false;
    signSecretPurpose = "";
    showMain();
    return;
  }
  if (approved) {
    PrivateKey pk(secKey);
    SchnorrSignature sig = pk.schnorr_sign(signDigest);
    uint8_t sigBytes[64];
    sig.serialize(sigBytes, 64);
    if (signIsEvent) {
      reply(signReplyCmd.c_str(), toHex(signDigest, 32) + " " + toHex(sigBytes, 64));
    } else {
      reply(signReplyCmd.c_str(), toHex(sigBytes, 64));
    }
  } else {
    reply(signReplyCmd.c_str(), signRejectReply);
  }
  memset(signDigest, 0, 32);
  showMain();
}

static void startSignJob(const char* cmd, const String& rejectReply,
                         const String& timeoutReply, bool isEvent) {
  signReplyCmd = cmd;
  signRejectReply = rejectReply;
  signTimeoutReply = timeoutReply;
  signIsEvent = isEvent;
  signIsSecret = false;
  showSignRequest();
}

static void startSecretJob(const uint8_t peerSec[33], const String& purpose) {
  signReplyCmd = "/shared-secret";
  signRejectReply = "rejected";
  signTimeoutReply = "timeout";
  signIsEvent = false;
  signIsSecret = true;
  signSecretPurpose = purpose;
  memcpy(pendingPeerSec, peerSec, 33);
  showSignRequest();
}

// ---------- NIP-04 shared secret ----------

// Accepts 128-hex X||Y (horse), 130-hex 04-prefixed, 66-hex compressed,
// or 64-hex x-only. Only the X coordinate is used: the point is lifted via
// the SEC compressed parser, which guarantees it lies on the curve (the
// client's Y is never trusted) — Y parity does not change the ECDH x result.
// uBitcoin's raw PublicKey(xy[64]) constructor yields wrong ecdh output, so
// everything must go through parse() (verified on hardware 2026-07-14).
static bool parsePeerPubkey(String hex, PublicKey& out, uint8_t secOut[33]) {
  hex.trim();
  hex.toLowerCase();
  if (hex.length() == 130 && hex.startsWith("04")) hex = hex.substring(2);
  if (hex.length() == 66 && (hex.startsWith("02") || hex.startsWith("03")))
    hex = hex.substring(2);
  if (hex.length() == 128) hex = hex.substring(0, 64);
  if (hex.length() != 64) return false;

  uint8_t sec[33];
  sec[0] = 0x02;
  fromHex(hex, sec + 1, 32);
  out = PublicKey(sec);
  if (secOut) memcpy(secOut, sec, 33);
  return out.isValid();
}

// ---------- serial ----------

static void handleSerialLine(String line) {
  line.trim();
  if (line.isEmpty()) return;

  String cmd = line;
  String data = "";
  int sp = line.indexOf(' ');
  if (sp > 0) {
    cmd = line.substring(0, sp);
    data = line.substring(sp + 1);
    data.trim();
  }

  if (cmd == "/ping") {
    // lnbits protocol: bare ping gets no reply (used to flush the buffer);
    // ping with a host token identifies the client
    if (!data.isEmpty()) {
      pairedHost = data;
      reply("/ping", "0 " + deviceId());
      if (screen == Screen::MAIN) showMain();
    }
  } else if (cmd == "/version") {
    reply("/version", "nostr-signer-s3 v" FW_VERSION);
  } else if (cmd == "/last-button") {
    reply("/last-button", lastButton);
  } else if (cmd == "/public-key") {
    // locked device reveals nothing, not even the (public) npub — a found
    // device should not identify its owner
    reply("/public-key",
          haveKey ? pubHex : (isLocked() ? "error: locked" : "error: no-key"));
  } else if (cmd == "/npub") {
    reply("/npub",
          haveKey ? npub : (isLocked() ? "error: locked" : "error: no-key"));
  } else if (cmd == "/shared-secret") {
    if (isLocked()) {
      reply("/shared-secret", "error: locked");
      drawLockedHint();
    } else if (!haveKey) {
      reply("/shared-secret", "error: no-key");
    } else if (screen == Screen::SIGN) {
      reply("/shared-secret", "busy");
    } else {
      // optional second token is a display-only "send"/"receive" hint (see
      // showSignRequest()) -- not part of the crypto, purely cosmetic.
      String peerHex = data;
      String purpose = "";
      int sp2 = data.indexOf(' ');
      if (sp2 > 0) {
        peerHex = data.substring(0, sp2);
        purpose = data.substring(sp2 + 1);
        purpose.trim();
      }
      PublicKey peer;
      uint8_t peerSec[33];
      if (!parsePeerPubkey(peerHex, peer, peerSec)) {
        reply("/shared-secret", "error: bad-pubkey");
      } else {
        // NIP-04 secret = raw x coordinate of the ECDH point (not hashed);
        // same primitive NIP-44/NIP-17 DMs derive their conversation key
        // from. Gated behind physical approval like signing -- see
        // showSignRequest()'s SHARE SECRET? screen for why this changed
        // from an instant, silent reply.
        startSecretJob(peerSec, purpose);
      }
    }
  } else if (cmd == "/sign-message") {
    if (isLocked()) {
      // "Rejected" is a valid protocol token — LNbits horse handles it cleanly
      reply("/sign-message", "Rejected");
      drawLockedHint();
    } else if (!haveKey) {
      reply("/sign-message", "error: no-key");
    } else if (screen == Screen::SIGN) {
      reply("/sign-message", "busy");
    } else if (data.length() != 64) {
      reply("/sign-message", "error: expected 64 hex chars");
    } else {
      fromHex(data, signDigest, 32);
      startSignJob("/sign-message", "Rejected", "Rejected", false);
    }
  } else if (cmd == "/sign-event") {
    if (isLocked()) {
      reply("/sign-event", "error locked");
      drawLockedHint();
    } else if (!haveKey) {
      reply("/sign-event", "error no-key");
    } else if (screen == Screen::SIGN) {
      reply("/sign-event", "busy");
    } else {
      String err = nostrEventId(data, pubHex, signEvent, signDigest);
      if (!err.isEmpty()) {
        reply("/sign-event", "error " + err);
      } else {
        startSignJob("/sign-event", "rejected", "timeout", true);
      }
    }
  } else if (cmd == "/restore-ready") {
    // Lets a host (recover.flink.club) poll whether it's safe to show the
    // word-entry UI yet -- only "armed" while the user has physically tapped
    // RESTORE on the device and the 5-minute window hasn't expired.
    if (keystoreHasVault() || keystoreHasLegacyKey() || haveKey) {
      reply("/restore-ready", "error: key-exists");
    } else if (screen == Screen::RESTORE_WAIT && restoreArmed && millis() < restoreArmedUntil) {
      reply("/restore-ready", "armed");
    } else {
      reply("/restore-ready", "not-armed");
    }
  } else if (cmd == "/restore-words") {
    // Fresh-device only, AND only while armed (see /restore-ready above) --
    // requires the user to have physically tapped RESTORE on the device
    // first, so a host can't silently provision a fresh device on its own.
    // The words travel over serial here (a one-time, break-glass trust of
    // the host at recovery time); the PIN that then encrypts them is still
    // entered on-device only, same as every other setup path.
    if (keystoreHasVault() || keystoreHasLegacyKey() || haveKey) {
      reply("/restore-words", "error: key-exists");
    } else if (screen != Screen::RESTORE_WAIT || !restoreArmed || millis() >= restoreArmedUntil) {
      reply("/restore-words", "error: not-armed");
    } else {
      String words[MNEMONIC_WORDS];
      int count = 0;
      String rest = data;
      rest.trim();
      while (rest.length() && count < MNEMONIC_WORDS) {
        int sp2 = rest.indexOf(' ');
        String w = (sp2 < 0) ? rest : rest.substring(0, sp2);
        rest = (sp2 < 0) ? "" : rest.substring(sp2 + 1);
        rest.trim();
        w.trim();
        w.toLowerCase();
        if (w.isEmpty()) continue;
        words[count++] = w;
      }
      if (count != MNEMONIC_WORDS) {
        reply("/restore-words", "error: need exactly 12 words");
      } else {
        String joined;
        for (int i = 0; i < MNEMONIC_WORDS; i++) {
          if (i) joined += " ";
          joined += words[i];
        }
        if (!checkMnemonic(joined)) {
          reply("/restore-words", "error: bad-checksum");
        } else {
          pendingMnemonic = joined;
          setupIsLegacyMigration = false;
          setupPhase = 0;
          setupFromGenerate = true;
          restoreArmed = false;  // window served its purpose, close it
          reply("/restore-words", "ok");
          showSetPin("Set a PIN first", TFT_YELLOW);
        }
      }
    }
  } else if (cmd == "/erase-request") {
    // Wipes the on-device key -- but only after a 3s physical HOLD on the
    // device itself (ERASE_CONFIRM screen), same physical-presence reasoning
    // as /restore-words: a host should not be able to destroy an existing
    // key the instant it connects. Only valid from MAIN or LOCKED (a key
    // must exist, and the device can't be mid some other flow).
    if (!(keystoreHasVault() || keystoreHasLegacyKey() || haveKey)) {
      reply("/erase-request", "error: no-key");
    } else if (screen != Screen::MAIN && screen != Screen::LOCKED) {
      reply("/erase-request", "error: busy");
    } else {
      showEraseConfirm();
      reply("/erase-request", "ok");
    }
  } else if (cmd == "/selftest-nip06") {
    // TEMPORARY diagnostic — derives from the official NIP-06 test vector's
    // mnemonic entirely in RAM, no NVS/vault access at all, so it's safe to
    // run on a device that already has a real key. Compare the reply against
    // https://github.com/nostr-protocol/nips/blob/master/06.md :
    //   pubkey 17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917
    //   npub   npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu
    String testMnemonic =
        "leader monkey parrot ring guide accident before fence cannon "
        "height naive bean";
    uint8_t testKey[32];
    deriveFromMnemonic(testMnemonic, testKey);
    PrivateKey pk(testKey);
    String testPubHex = pk.publicKey().toString().substring(2);
    uint8_t testPubBytes[32];
    fromHex(testPubHex, testPubBytes, 32);
    String testNpub = bech32Encode("npub", testPubBytes, 32);
    memset(testKey, 0, sizeof(testKey));
    reply("/selftest-nip06", testPubHex + " " + testNpub);
  } else {
    reply("/error", "unknown-command " + cmd);
  }
}

// ---------- arduino ----------

void setup() {
  // keep the panel powered when running from battery
  pinMode(PIN_LCD_POWER, OUTPUT);
  digitalWrite(PIN_LCD_POWER, HIGH);

  pinMode(PIN_BTN_BOOT, INPUT_PULLUP);
  pinMode(PIN_BTN_KEY, INPUT_PULLUP);

  // Default USB-CDC driver RX ring buffer is small (a couple hundred bytes)
  // and silently drops bytes once full — a real event line (e.g. a kind-3
  // follow list with 2+ p-tags, ~300+ bytes) can outrun it before loop()
  // drains it, truncating the JSON (deserializeJson then fails as
  // IncompleteInput). Must be called before Serial.begin().
  Serial.setRxBufferSize(RX_MAX);
  Serial.begin(115200);

  tft.init();
  tft.setRotation(1);  // landscape, 320x170, buttons on the right
  tft.setBrightness(180);
  tft.setTextSize(2);

  if (keystoreHasVault()) {
    startBackoff();  // resume the penalty for pre-reboot wrong attempts
    showLocked("Enter PIN", TFT_LIGHTGREY);
  } else if (keystoreLoadLegacy(pendingKey)) {
    // v0.0.3 plaintext key found: force PIN setup, then re-store encrypted
    // as a legacy raw-key vault -- there was never a mnemonic for this key.
    setupIsLegacyMigration = true;
    setupPhase = 0;
    setupFromGenerate = false;
    showSetPin("Protect your key", TFT_YELLOW);
  } else {
    showNoKey();
  }

  Serial.println("nostr-signer-s3 v" FW_VERSION " ready");
}

// Set once a held-top-button action has fired (NEW KEY / BACKUP SHOW /
// ERASE), cleared only on release. Without this, a hold that crosses the
// threshold right as it triggers a screen transition would immediately
// re-trigger whatever hold-action the NEW screen also binds to top button --
// concretely, ERASE_CONFIRM's hold-to-confirm transitions straight into
// NOKEY, which has its own hold-to-generate on the same button; the next
// loop() tick would see "still held past 3s" and instantly generate a new
// key right behind the erase, with no additional hold required (confirmed
// live on hardware 2026-07-19: erase completed but a new key appeared
// instead of the NOKEY screen).
static bool topHoldConsumed = false;

void loop() {
  btnTop.poll();
  btnBottom.poll();
  if (btnTop.tapped()) lastButton = "top (gpio14)";
  if (btnBottom.tapped()) lastButton = "bottom (gpio0)";
  if (btnTop.changed && !btnTop.pressed) topHoldConsumed = false;  // released: re-arm

  switch (screen) {
    case Screen::NOKEY:
      if (btnTop.pressed && !topHoldConsumed && millis() - btnTop.lastEdgeMs > GENERATE_HOLD_MS) {
        topHoldConsumed = true;
        uint8_t entropy[16];
        keystoreGenerateEntropy(entropy);
        pendingMnemonic = String(mnemonicFromEntropy(entropy, sizeof(entropy)));
        memset(entropy, 0, sizeof(entropy));
        setupIsLegacyMigration = false;
        setupPhase = 0;
        setupFromGenerate = true;  // QR reveal comes after the vault is sealed
        showSetPin("Set a PIN first", TFT_YELLOW);
      } else if (btnTop.pressed || btnTop.changed) {
        drawNoKeyHoldLine();  // live countdown while held, restore text on release
      } else if (btnBottom.tapped()) {
        armRestore();
      }
      break;

    case Screen::LOCKED:
      if (backoffUntil && millis() < backoffUntil) {
        drawBackoff();
      } else {
        if (backoffUntil) {  // penalty just expired: clear the countdown line
          backoffUntil = 0;
          showLocked("Enter PIN", TFT_LIGHTGREY);
        }
        handlePinInput();
      }
      break;

    case Screen::SETPIN:
      handlePinInput();
      break;

    case Screen::MAIN:
      if (btnBottom.tapped()) {
        showQr();
      } else if (btnTop.tapped()) {
        if (curMnemonic.isEmpty()) {
          tft.setTextColor(TFT_ORANGE, TFT_BLACK);
          tft.setCursor(10, 148);
          tft.print("no backup for this key");
        } else {
          showBackupWarn();
        }
      }
      break;

    case Screen::QR:
      if (btnTop.tapped() || btnBottom.tapped()) showMain();
      break;

    case Screen::SIGN:
      if (btnTop.tapped()) {
        finishSign(true);
      } else if (btnBottom.tapped()) {
        finishSign(false);
      } else if (millis() - signRequestedAt > SIGN_TIMEOUT_MS) {
        reply(signReplyCmd.c_str(), signTimeoutReply);
        memset(signDigest, 0, 32);
        memset(pendingPeerSec, 0, sizeof(pendingPeerSec));
        signIsSecret = false;
        signSecretPurpose = "";
        showMain();
      }
      break;

    case Screen::BACKUP_WARN:
      if (btnTop.pressed && !topHoldConsumed && millis() - btnTop.lastEdgeMs > GENERATE_HOLD_MS) {
        topHoldConsumed = true;
        showBackupPage();
      } else if (btnTop.pressed || btnTop.changed) {
        drawBackupShowHoldLine();  // live countdown while held, restore text on release
      } else if (btnBottom.tapped()) {
        showMain();
      }
      break;

    case Screen::BACKUP_SHOW:
      if (btnBottom.tapped()) {
        backupPage = (backupPage + 1) % 3;
        drawBackupPage();
      } else if (btnTop.tapped()) {
        for (int i = 0; i < MNEMONIC_WORDS; i++) backupWords[i] = "";
        showMain();
      }
      break;

    case Screen::RESTORE_WAIT:
      handleRestoreWaitInput();
      break;

    case Screen::ERASE_CONFIRM:
      if (btnTop.pressed && !topHoldConsumed && millis() - btnTop.lastEdgeMs > GENERATE_HOLD_MS) {
        topHoldConsumed = true;
        performErase();
      } else if (btnTop.pressed || btnTop.changed) {
        drawEraseHoldLine();  // live countdown while held, restore text on release
      } else if (btnBottom.tapped()) {
        cancelEraseConfirm();
      }
      break;
  }

  static String rxLine;
  static bool rxOverflow = false;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (rxOverflow) {
        reply("/error", "line-too-long");
      } else {
        handleSerialLine(rxLine);
      }
      rxLine = "";
      rxOverflow = false;
    } else if (rxLine.length() < RX_MAX) {
      rxLine += c;
    } else {
      rxOverflow = true;
    }
  }

  delay(5);
}
