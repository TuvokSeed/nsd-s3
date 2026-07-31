# nostr-signer-s3

Nostr hardware signing device for the **LilyGo T-Display S3** (ESP32-S3, 1.9" ST7789
170x320 on an 8-bit parallel bus, native USB, two buttons).

The private key lives on the device and never touches the computer. Signing requests
arrive over USB (WebSerial), a summary is shown on the display, and a physical button
press approves or rejects.

## Status

**v0.0.11 — key generation gets a real hardware entropy source.** With no
Wi-Fi/BT running (this firmware runs neither), `esp_random()` on the ESP32-S3
is only pseudo-random — the hardware RNG register keeps updating but has no
entropy source feeding it, the same silent-fallback failure shape as the 2026
Coldcard Mk3 bug. Mnemonic entropy and vault salts/nonces were drawn that way.
Now every key-material draw enables the RF-independent bootloader entropy
source for its duration and is additionally mixed (SHA-256) with a pool
stirred by button-press timings, so no single failure can degrade the output.
Seeds generated on earlier firmware should be rotated once convenient.

**v0.0.10 — `/shared-secret` shows what it's for.** Receiving a NIP-17 DM
needs two separate approvals in a row (the ephemeral outer wrap, then the
sender's real-pubkey seal), and it wasn't obvious on-device which was which.
The command now takes an optional second token, `send` or `receive` — a
display-only hint from the host, no cryptographic weight — and the SHARE
SECRET? screen shows "Sending message" / "Receiving message" accordingly.
Callers that don't send it (lnbits horse, `tools/protocol-test.py`) still
get the old generic "DM key exchange" text.

**v0.0.9 — `/shared-secret` requires physical approval, no more silent replies.**
It used to answer instantly with no button press at all (an accommodation for
the lnbits horse extension, which only waits 6s for a reply). That meant any
host holding an open serial connection to an *unlocked* device could silently
pull the ECDH secret for any peer pubkey — no screen prompt, nothing. Since
NIP-17 DMs (flink.club) derive their NIP-44 conversation key from this exact
primitive, that silent path could read or forge a user's private messages
with zero on-device confirmation. Now routed through the same approval
state machine as `/sign-message`/`/sign-event`: a **SHARE SECRET?** screen
shows the peer pubkey's prefix and requires ALLOW/DENY, same as signing.
New reply tokens `busy` / `rejected` / `timeout` alongside the existing
64-hex success reply. Known, accepted tradeoff: the lnbits horse extension's
6s wait will now generally time out unless answered fast — it was built
around the old silent behavior and has no concept of a pending approval.

**v0.0.8 — in-firmware key erase, no flasher needed.** recover.flink.club's
"device already has a key" screen used to send people to flash.flink.club's
full chip-erase option — which also wipes the firmware (a reflash is then
needed before the device works again), and can't even be done from the same
tab anyway, since WebSerial ports are exclusive and a second tab can't open a
port the first tab already holds. A new `/erase-request` command instead puts
the device into an **ERASE?** screen (reachable only from MAIN or LOCKED, i.e.
only when a key exists); a 3s physical HOLD wipes just this app's NVS
namespace (vault + fail-counter + any legacy remnant) and returns to NOKEY —
firmware stays intact, no reflash needed. Same physical-presence reasoning as
v0.0.7's RESTORE hardening below: a host shouldn't be able to destroy an
existing key the instant it connects.
- **Real bug found and fixed during hardware testing:** NOKEY's own
  "hold top button 3s to generate a new key" and ERASE_CONFIRM's "hold top
  button 3s to wipe" share the same gesture, and erase transitions straight
  into NOKEY — so if the physical hold ran even slightly past 3s, the very
  next loop tick would see "button already held past threshold" on the new
  screen and instantly generate a fresh key right behind the erase, with no
  extra hold required. Confirmed live: an erase completed but a brand-new key
  appeared instead of a bare NOKEY screen. Fixed with a `topHoldConsumed` latch
  that's set on any hold-triggered action and only clears on button release,
  applied to all three hold gestures (NEW KEY, BACKUP show, ERASE) for
  consistency.

**v0.0.7 — restore now requires physical presence on the device.** Previously a
fresh device would derive a key from any 12 words sent over serial the moment
it booted with no vault — nothing on the device confirmed this, so a script
running on an untrusted host could silently provision it the instant it was
plugged in. Now `RESTORE` on the NOKEY screen arms a 5-minute window
(`error: not-armed` outside it) before `/restore-words` is accepted at all,
polled with the new `/restore-ready` command. This also **replaces the
on-device 2048-word-per-slot scroll picker** — that fully-air-gapped path is
gone in favor of typing on [recover.flink.club](https://recover.flink.club),
which is faster and, via a scrambled on-screen keyboard, doesn't expose the
words to a physical-keyboard logger either.

**v0.0.6 — proper NIP-06: the key is BIP-32 HD-derived from a 12-word BIP-39
mnemonic** (`m/44'/1237'/0'/0/0`, standard Nostr derivation, no passphrase),
using uBitcoin's vendored Trezor bip39/bip32 crypto (`HDPrivateKey`). The
mnemonic itself — not a raw key — is what's encrypted in the vault, since a
derived key can never be reversed back into the words that produced it.
Verified the exact algorithm against both official NIP-06 test vectors in an
independent Python re-implementation before writing any device code, and
again on the real compiled firmware via a temporary `/selftest-nip06` command
(derives from the fixed test mnemonic in RAM only, touches no vault/state —
useful to re-check after any crypto-adjacent change).

- **Reveal** (MAIN screen, hold the top button 3s — same gesture as NEW KEY,
  changed from a plain tap after real-world use: a single accidental tap was
  too easy to trigger for something this sensitive) shows the 12 words
  on-device only, never over serial.
- **Restore** (NOKEY screen, tap `RESTORE >`) arms a 5-minute window during
  which the one-time serial `/restore-words w1..w12` is accepted — see v0.0.7
  above. Checksum validated via the standard `checkMnemonic()`.
- **Watchdog gotcha (real, not cosmetic):** the seed PBKDF2 (2048 rounds) plus
  the two non-hardened BIP-32 levels (each a full secp256k1 point
  multiplication) take ~7s combined. Run as one blocking call this never
  yields back to FreeRTOS and trips the ESP32 task watchdog, silently
  rebooting the device mid-derivation (confirmed via a real USB disconnect
  while debugging). Fixed by walking the 5-level path one `child()` at a
  time with `delay(1)` between each step instead of one `derive(path)` call
  — same breakpoints also drive a progress bar so PIN unlock and first-time
  setup aren't a silent multi-second freeze.
- **Pre-v0.0.6 vaults still unlock fine** (raw 32-byte key, no mnemonic
  behind it, `keystoreUnlock()` reports which kind it found) — `BACKUP`
  correctly shows "no backup for this key" for those rather than crashing,
  since there's no mnemonic to reveal for a key that predates this scheme.

Vault blob (NVS `nsd/vault`, recoverable off-device with the PIN):
- v1 (legacy raw key, 81 bytes): `ver=1 | pbkdf2-iters u32 LE | salt(16) | gcm-nonce(12) | ciphertext(32) | tag(16)`
- v2 (mnemonic, 177 bytes): `ver=2 | pbkdf2-iters u32 LE | salt(16) | gcm-nonce(12) | ciphertext(128, 1-byte length + up to 127 mnemonic chars) | tag(16)`

**v0.0.4 — PIN lock: key encrypted at rest + auto-lock.** Boot starts locked —
PIN entry is a two-button digit picker (bottom cycles 0-9, top confirms).
Wrong PINs get exponential backoff (2s…60s, counter survives power cycles);
the key is **never wiped** by failed attempts. Unlock lasts until power-off —
the board is USB-powered, so unplugging is the lock. While locked the device
reveals nothing — even `/public-key` answers `error: locked` (a found device
should not identify its owner); `/sign-message` answers `Rejected` for horse
compat. Keys from v0.0.3 and earlier are migrated on first boot: set a PIN,
the key is re-stored encrypted (as a legacy v1 vault — there was never a
mnemonic for those) and the plaintext copy deleted.

**v0.0.3 — LNbits-NSD-compatible protocol + event-aware signing.** Speaks the
serial protocol of the [lnbits/nostr-signing-device](https://github.com/lnbits/nostr-signing-device),
so the [horse](https://github.com/lnbits/horse) and nos2x-nsd browser extensions
work unmodified. On top of that, the `/sign-event` extension receives the **full
event JSON**, computes the NIP-01 id **on the device** (the client's digest is
never trusted — the device only signs what it displays) and shows an event-aware
approval screen: kind, recipient (first `p` tag) and a content preview.

Buttons (landscape, USB right): **top** = approve / generate, **bottom** =
reject / toggle QR.

## Serial protocol

115200 baud (native USB CDC — the host's baud setting is ignored, horse's 9600
works fine), newline-terminated lines. Replies are framed `/method <data>` as
the lnbits extensions expect.

LNbits-NSD compatible:

| command                  | reply                                              |
|--------------------------|----------------------------------------------------|
| `/ping`                  | *(none — flushes the line buffer)*                 |
| `/ping <host>`           | `/ping 0 <device-id>` (host shown on display)      |
| `/public-key`            | `/public-key <64hex x-only>`                       |
| `/sign-message <64hex>`  | after button: `/sign-message <128hex sig>`, else `/sign-message Rejected` (also on 60s timeout) |
| `/shared-secret <peer> [send\|receive]` | approval screen ("SHARE SECRET?", labelled "Sending"/"Receiving message" if the optional purpose token is given, else generic); after button: `/shared-secret <64hex ecdh-x>` (NIP-04/NIP-44 raw ECDH x-coordinate) \| `rejected` \| `timeout` (60s) \| `busy` (another request already showing). peer as 128-hex X‖Y (horse), 130-hex `04…`, 66-hex compressed, or 64-hex x-only. **Not** answered within lnbits horse's 6s window unless you're fast — was silent/instant before v0.0.9, deliberately no longer is. |

Extensions (this device only — used by flink.club and `tools/protocol-test.py`):

| command                | reply                                                |
|------------------------|------------------------------------------------------|
| `/sign-event <json>`   | event-aware approval screen; `/sign-event <64hex id> <128hex sig>` \| `rejected` \| `timeout` \| `error <token>`. Requires `created_at` (device has no clock); `pubkey` optional but must match the device key; id computed on-device. Max line 8 KB. |
| `/version`             | `/version nostr-signer-s3 v0.0.11`                   |
| `/npub`                | `/npub npub1...`                                     |
| `/last-button`         | `/last-button <which>` (debug)                       |
| `/restore-ready`       | `armed` \| `not-armed` \| `error: key-exists`. Poll after connecting — only `armed` while the user has tapped `RESTORE >` on the device within the last 5 minutes. |
| `/restore-words w1..w12` | `/restore-words ok` \| `error <reason>`. Fresh-device only **and** only while armed (see `/restore-ready`) — otherwise `error: not-armed` even with no vault at all. Standard NIP-06: checksum validated via `checkMnemonic()`, key BIP-32 HD-derived from the words. PIN is still set on-device afterward. |
| `/erase-request`       | `ok` \| `error: no-key` \| `error: busy`. Only valid on MAIN or LOCKED (a key must exist). Puts the device into an ERASE-CONFIRM screen requiring a 3s physical HOLD to actually wipe — CANCEL on that screen aborts. Wipes the NVS vault only, **not** a full chip erase (firmware stays intact, no reflash needed after). |
| `/selftest-nip06`      | `/selftest-nip06 <64hex pubkey> <npub>` — TEMPORARY diagnostic, derives from the fixed official NIP-06 test mnemonic in RAM only (no vault/state touched). Remove once no longer needed. |

## Roadmap

1. ~~Board bring-up: display (LovyanGFX), buttons, USB CDC~~ (v0.0.1)
2. ~~Crypto core: BIP-340 Schnorr (uBitcoin), hardware-RNG key in NVS, npub QR~~ (v0.0.2)
3. ~~LNbits-NSD-compatible serial protocol + event-aware approve/reject UI~~ (v0.0.3)
4. ~~WebSerial signer module in flink.club (talks `/sign-event` directly, no extension)~~ (live 2026-07-15)
5. ~~PIN on boot, key encrypted at rest~~ (v0.0.4; idle auto-lock built then dropped — PIN on power-up only)
6. ~~nsec backup~~ (v0.0.5 shipped a raw-key 24-word codec same day, superseded
   hours later by v0.0.6's proper NIP-06 12-word mnemonic — see Status above
   and main.cpp header). Still open: key slots; optional approve-per-secret
   for NIP-04
7. ~~Web flasher~~ — `flasher/` in this repo: ESP Web Tools static page (vendored
   `esp-web-tools@10.4.0`, Apache-2.0, no CDN), manifest parts bootloader @ 0x0 (S3!),
   partitions @ 0x8000, boot_app0 @ 0xe000, firmware @ 0x10000. `flasher/deploy.sh`
   builds, copies bins from `.pio/build/tdisplay-s3/` + the framework's boot_app0.bin,
   stamps `manifest.json` with the git hash + firmware.bin sha256 (shown on the page),
   and (with `--deploy`) scps to your own web root (copy `deploy.env.example` to
   `deploy.env` and fill in your server). NOTE (2026-07-31, field-tested): a web
   flash always FULL-ERASES the device including the NVS vault — esp-web-tools
   only offers a data-preserving update when it recognizes the running firmware
   via Improv serial, which NSD doesn't implement, so every web install is a
   "new install" with a mandatory erase. Only `pio run -t upload` preserves the
   vault; the page warns to back up words before flashing. Implementing Improv
   (web updates that keep the key) = candidate for a future version. Verified headlessly (chrome-headless-shell + CDP): custom element registers,
   WebSerial detected, manifest loads, zero console errors/failed requests. Live at
   [flash.flink.club](https://flash.flink.club).
8. Later: NIP-46 WiFi bunker mode (sign for mobile clients via relay)

## Build & flash

```sh
pio run                    # compile
pio run -t upload          # flash over USB-C
pio device monitor         # serial console
python3 tools/protocol-test.py   # end-to-end protocol test (pip install pyserial)
```

Board notes:

- GPIO15 must be driven HIGH or the display stays dark on battery power.
- Buttons: BOOT = GPIO0 (left), KEY = GPIO14 (right), active-low.
- First flash on a factory board may require holding BOOT while plugging in
  (enters the ROM bootloader), then a manual reset after flashing.
- WebSerial (for the browser extension / flink) is Chromium-only.

## Prior art

- [lnbits/nostr-signing-device](https://github.com/lnbits/nostr-signing-device) —
  same idea on the old TTGO T-Display (SPI, classic ESP32); we speak its serial
  protocol so its browser extensions work with this device
- [lnbits/arduino-nostr](https://github.com/lnbits/arduino-nostr)
- [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
