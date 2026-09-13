/*
 * HID Reader Recon -- Flipper Zero NFC card-emulation port of hid_rm's
 * BLE-based protocol responder (emulate.py / leak.py from the HID Reader
 * Manager research). Emulates the ISO14443-4A "STANDARD_SEOS" credential so a
 * HID Signo/iCLASS SE/MultiClass SE reader's own NFC discovery loop will poll
 * and select this device, exactly mirroring what was reverse-engineered over
 * BLE this session: the reader always drives the exchange (it's the ISO7816
 * terminal / PCD role); this app only needs to answer with a valid status
 * word (9000) to whatever it sends, and log/decode the SELECT ADF (credential
 * OID) and SELECT AID (mode) commands it offers along the way.
 *
 * Protocol facts this app encodes (see ~/hid/PROTOCOL.md and AAMK.md for the
 * full derivation):
 *   - STANDARD_SEOS AID (16 bytes, live-verified): A0 00 00 04 40 00 01 01 00
 *     01 00 00 47 05 2B 03 (Constants.AID.STANDARD_SEOS base + a 6-byte
 *     qualifier).
 *   - SELECT ADF (CLA=0x80, INS=0xA5) carries a list of tag-0x06 DER OIDs --
 *     the reader's configured SEOS PACS credential objects (the "config
 *     leak").
 *   - SELECT AID (CLA=0x00, INS=0xA4) can also offer other fixed AIDs (the
 *     admin/updater/passthrough set from HidGlobal.ArtemisManager
 *     Constants.AID) -- classified below.
 *   - The reader only checks the trailing status word of our reply; content
 *     otherwise is irrelevant (live-proven in the BLE work) -- so we always
 *     answer 90 00.
 */

#include <furi.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/view_port.h>
#include <input/input.h>

#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>

#include <storage/storage.h>

#include <string.h>
#include <stdio.h>

#define TAG "HidRecon"
#define MAX_OIDS 24
#define OID_STR_LEN 56 /* fixed after live test: 40 was truncating real OIDs,
                          e.g. "...1.24.1.6.1.1.10" instead of "...10664" */
#define MAX_AIDS 8
#define AID_STR_LEN 40
#define LAST_EVENT_LEN 56
#define LOG_PATH "/ext/apps_data/hid_recon/session.txt"
/* Auto-exit after this long, regardless of button input. This makes the app
 * safe to test via the CLI/RPC alone: no remote input delivery or app-close
 * signal is depended on to get back to a clean state. Physical Back/OK still
 * work for interactive use in the meantime. */
#define AUTO_EXIT_MS (30 * 1000)

/* ---- Known AID table (ported from hid_rm/emulate.py AID dict) ---- */
typedef struct {
    const char* name;
    uint8_t aid[10];
} KnownAid;

static const KnownAid known_aids[] = {
    {"SAM_UPDATER", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x28, 0x00, 0x01, 0x01}},
    {"BLE_CORE_UPDATER", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x29, 0x00, 0x01, 0x01}},
    {"NFC_CORE_UPDATER", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x21, 0x00, 0x01, 0x01}},
    {"NFC_OEM_CORE_UPDATER", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x25, 0x00, 0x01, 0x01}},
    {"DOTNETAPP_ADMIN", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2B, 0x00, 0x01, 0x01}},
    {"PASSTHROUGH", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2C, 0x00, 0x01, 0x01}},
    {"MOBILE_SEOS_ADMIN_CARD", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2D, 0x00, 0x01, 0x01}},
    {"OPERATION_SELECTOR", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2F, 0x00, 0x01, 0x01}},
    {"OPERATION_SELECTOR_POST_RESET", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x31, 0x00, 0x01, 0x01}},
    {"LEGACY_PASSTHROUGH", {0xA0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x30, 0x00, 0x01, 0x01}},
};
#define KNOWN_AID_COUNT (sizeof(known_aids) / sizeof(known_aids[0]))

static const uint8_t standard_seos_base[10] = {0xA0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01};

/* ---- NFC robustness/fuzz cases -----------------------------------------
 * Port of hid_rm/fuzz.py's malformed-reply cases to the NFC transport (the
 * BLE run of these found no crash; this tests whether the reader's NFC
 * front-end -- plausibly different silicon/firmware -- is equally robust).
 * Cycled one per received APDU (FUZZ_MODE=1) instead of always answering
 * plain 9000, so a single session exercises several cases automatically as
 * the reader retries. Config data (OIDs/AIDs) is still parsed regardless of
 * which case is used, via handle_apdu() before the reply is chosen. ---- */
#define FUZZ_MODE 0 /* AKE-capture build: always reply 9000 to keep the reader talking as far into the SEOS exchange as possible */
#if FUZZ_MODE
typedef struct {
    const char* name;
    const uint8_t* bytes;
    size_t len;
} FuzzCase;

static const uint8_t fz_sw_9000[]      = {0x90, 0x00};
static const uint8_t fz_sw_0000[]      = {0x00, 0x00};
static const uint8_t fz_sw_6a82[]      = {0x6A, 0x82};
static const uint8_t fz_sw_61ff[]      = {0x61, 0xFF};
static const uint8_t fz_sw_truncated[] = {0x90};
static const uint8_t fz_fci_lie[]      = {0x6F, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, 0x90, 0x00};
static const uint8_t fz_empty[]        = {0};

static const FuzzCase fuzz_cases[] = {
    {"9000 (control)", fz_sw_9000, sizeof(fz_sw_9000)},
    {"SW=0000", fz_sw_0000, sizeof(fz_sw_0000)},
    {"SW=6A82", fz_sw_6a82, sizeof(fz_sw_6a82)},
    {"SW=61FF (GET RESPONSE)", fz_sw_61ff, sizeof(fz_sw_61ff)},
    {"truncated (1 byte)", fz_sw_truncated, sizeof(fz_sw_truncated)},
    {"FCI length lie", fz_fci_lie, sizeof(fz_fci_lie)},
    {"empty reply", fz_empty, 0},
    {"9000 (control)", fz_sw_9000, sizeof(fz_sw_9000)},
};
#define FUZZ_CASE_COUNT (sizeof(fuzz_cases) / sizeof(fuzz_cases[0]))
#endif /* FUZZ_MODE */

/* Plain-English gloss for each known technical AID name, so the app can
 * explain what the reader offered without the user needing to know what an
 * "AID" is. Ordering matches known_aids[] above; STANDARD_SEOS handled
 * separately since it's not in that table. */
static const char* english_for_aid(const char* technical_name) {
    if(strcmp(technical_name, "STANDARD_SEOS") == 0) return "Standard credential slot";
    if(strcmp(technical_name, "MOBILE_SEOS_ADMIN_CARD") == 0) return "Admin/management access mode";
    if(strcmp(technical_name, "OPERATION_SELECTOR") == 0) return "Mode selector";
    if(strcmp(technical_name, "OPERATION_SELECTOR_POST_RESET") == 0) return "Mode selector (post-reset)";
    if(strcmp(technical_name, "SAM_UPDATER") == 0) return "SAM firmware updater mode";
    if(strcmp(technical_name, "BLE_CORE_UPDATER") == 0) return "BLE firmware updater mode";
    if(strcmp(technical_name, "NFC_CORE_UPDATER") == 0) return "NFC firmware updater mode";
    if(strcmp(technical_name, "NFC_OEM_CORE_UPDATER") == 0) return "OEM NFC firmware updater mode";
    if(strcmp(technical_name, "DOTNETAPP_ADMIN") == 0) return "App admin interface";
    if(strcmp(technical_name, "PASSTHROUGH") == 0) return "Passthrough mode";
    if(strcmp(technical_name, "LEGACY_PASSTHROUGH") == 0) return "Legacy passthrough mode";
    return "Unrecognized application";
}

/* Does this technical AID name represent an admin/management/update-capable
 * mode, as opposed to the plain everyday credential slot? Used to surface a
 * single plain-English "admin mode present" fact rather than making the user
 * parse a list of AID names. */
static bool aid_is_admin_like(const char* technical_name) {
    return strcmp(technical_name, "STANDARD_SEOS") != 0;
}

/* ---- OID classification against the known PACS ADF tree (byte-level, on the
 * raw DER bytes -- port of hid_rm/oid_db.py's describe()/summarize()). ---- */
static const uint8_t standard_pacs_adf_oid[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38,
    0x01, 0x01, 0x02, 0x01, 0x18, 0x01, 0x01, 0x02, 0x02};
static const uint8_t pacs_adf_base[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x01, 0x18, 0x01};

typedef enum {
    OidKindStandard, /* exactly STANDARD_PACS_ADF_OID -- the generic HID default */
    OidKindCustom,   /* under the PACS ADF tree, but not the standard object --
                         a customer/deployment-specific credential */
    OidKindOther,    /* not recognised at all */
} OidKind;

static OidKind classify_oid(const uint8_t* der, size_t len) {
    if(len == sizeof(standard_pacs_adf_oid) && memcmp(der, standard_pacs_adf_oid, len) == 0) {
        return OidKindStandard;
    }
    if(len > sizeof(pacs_adf_base) && memcmp(der, pacs_adf_base, sizeof(pacs_adf_base)) == 0) {
        return OidKindCustom;
    }
    return OidKindOther;
}

/* ---- App state (shared between NFC callback thread and GUI thread) ---- */
typedef enum {
    PhaseIdle,
    PhaseActive,
    PhaseEnded,
} SessionPhase;

typedef struct {
    char oids[MAX_OIDS][OID_STR_LEN]; /* raw decoded OIDs, technical detail only */
    uint8_t oid_count;
    uint8_t oid_standard_count; /* how many were the generic HID default object */
    uint8_t oid_custom_count;   /* how many were customer/deployment-specific */
    uint8_t oid_other_count;    /* how many weren't recognised as PACS credentials at all */

    char aids[MAX_AIDS][AID_STR_LEN];          /* raw technical label (name or hex), for log detail */
    char aid_english[MAX_AIDS][48];             /* plain-English description, shown primarily */
    uint8_t aid_count;
    bool admin_mode_seen; /* true if the reader offered any admin/updater/mode-select AID */

    uint32_t exchange_count;
    uint32_t field_toggle_count;
    uint32_t fuzz_index;   /* next fuzz_cases[] entry to use as a reply (FUZZ_MODE) */
    char fuzz_last_case[32]; /* name of the fuzz case most recently sent, for the log */
    char last_event[LAST_EVENT_LEN]; /* always plain English -- no AIDs/OIDs/hex here */
    SessionPhase phase;
} ReconState;

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    FuriMessageQueue* input_queue;
    FuriMutex* mutex;
    ReconState state;

    Nfc* nfc;
    Iso14443_4aData* iso4a_data;
    NfcListener* listener;
    BitBuffer* tx_buffer;

    Storage* storage;
    /* Raw APDU transcript of the reader's commands (reader->emulated card),
     * captured full-hex so a live tap records the reader's post-SELECT SEOS
     * exchange -- crucially the authenticated key exchange (AKE) challenge the
     * reader issues once it thinks a credential is present. Kept OUT of
     * ReconState so it isn't copied onto the stack by save_log's snapshot. */
    char transcript[3072];
    uint16_t transcript_len;
    uint16_t transcript_apdu_count;

    bool running;
    volatile bool dirty; /* set by the NFC callback thread, drained by the GUI-update
                            cadence in the main loop -- avoids flooding view_port_update()
                            from a fast-repeating NFC event (observed: reader field
                            on/off every ~200ms during idle polling caused GUI lockup
                            warnings when updated unconditionally on every event). */
} HidReconApp;

/* ---- DER OID -> dotted string (port of hid_rm/oid.py decode()) ---- */
static void decode_oid(const uint8_t* data, size_t len, char* out, size_t out_size) {
    if(len == 0 || out_size == 0) {
        if(out_size) out[0] = '\0';
        return;
    }
    int pos = snprintf(out, out_size, "%u.%u", data[0] / 40, data[0] % 40);
    uint32_t val = 0;
    for(size_t i = 1; i < len && pos > 0 && (size_t)pos < out_size - 1; i++) {
        val = (val << 7) | (data[i] & 0x7F);
        if(!(data[i] & 0x80)) {
            pos += snprintf(out + pos, out_size - (size_t)pos, ".%lu", (unsigned long)val);
            val = 0;
        }
    }
}

static const char* classify_aid(const uint8_t* aid, size_t len) {
    for(size_t i = 0; i < KNOWN_AID_COUNT; i++) {
        if(len == 10 && memcmp(aid, known_aids[i].aid, 10) == 0) {
            return known_aids[i].name;
        }
    }
    if(len >= 10 && memcmp(aid, standard_seos_base, 10) == 0) {
        return "STANDARD_SEOS";
    }
    return NULL; /* unknown -- caller falls back to hex */
}

static bool state_add_oid(ReconState* state, const char* oid) {
    for(uint8_t i = 0; i < state->oid_count; i++) {
        if(strcmp(state->oids[i], oid) == 0) return false; /* dedup */
    }
    if(state->oid_count < MAX_OIDS) {
        strncpy(state->oids[state->oid_count], oid, OID_STR_LEN - 1);
        state->oids[state->oid_count][OID_STR_LEN - 1] = '\0';
        state->oid_count++;
        return true;
    }
    return false;
}

/* Returns true if `aid` (technical label/hex) is newly added. On success,
 * also fills in the plain-English description for display. */
static bool state_add_aid(ReconState* state, const char* aid, const char* english) {
    for(uint8_t i = 0; i < state->aid_count; i++) {
        if(strcmp(state->aids[i], aid) == 0) return false;
    }
    if(state->aid_count < MAX_AIDS) {
        strncpy(state->aids[state->aid_count], aid, AID_STR_LEN - 1);
        state->aids[state->aid_count][AID_STR_LEN - 1] = '\0';
        strncpy(state->aid_english[state->aid_count], english, sizeof(state->aid_english[0]) - 1);
        state->aid_english[state->aid_count][sizeof(state->aid_english[0]) - 1] = '\0';
        state->aid_count++;
        return true;
    }
    return false;
}

/* ---- Core protocol logic: parse the reader's APDU, decide the reply.
 * Mirrors hid_rm/leak.py's parse_select_adf/parse_select_aid + emulate.py's
 * "always answer 9000" responder. Everything the user sees (screen and
 * last_event) is described in plain English -- raw OID/AID technical detail
 * is still kept for the saved log, but is not the primary output. ---- */
/* Append one reader command APDU to the raw transcript (full hex), so a live
 * capture records the reader's SEOS AKE challenge sequence. Caller holds the
 * mutex. */
static void transcript_add(HidReconApp* app, const uint8_t* apdu, size_t len) {
    if((size_t)app->transcript_len + 8 >= sizeof(app->transcript)) return; /* full */
    app->transcript_apdu_count++;
    int n = snprintf(app->transcript + app->transcript_len,
                     sizeof(app->transcript) - app->transcript_len, "%02u< ",
                     (unsigned)(app->transcript_apdu_count % 100));
    if(n > 0) app->transcript_len += (uint16_t)n;
    for(size_t i = 0; i < len; i++) {
        if((size_t)app->transcript_len + 4 >= sizeof(app->transcript)) break;
        n = snprintf(app->transcript + app->transcript_len,
                     sizeof(app->transcript) - app->transcript_len, "%02X", apdu[i]);
        if(n > 0) app->transcript_len += (uint16_t)n;
    }
    if((size_t)app->transcript_len + 2 < sizeof(app->transcript)) {
        app->transcript[app->transcript_len++] = '\r';
        app->transcript[app->transcript_len++] = '\n';
        app->transcript[app->transcript_len] = '\0';
    }
}

static void handle_apdu(HidReconApp* app, const uint8_t* apdu, size_t len) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    ReconState* state = &app->state;
    state->exchange_count++;
    state->phase = PhaseActive;
    transcript_add(app, apdu, len);

    if(len >= 5 && apdu[1] == 0xA5) {
        /* SELECT ADF: CLA INS P1 P2 Lc [ 06 len OID ]* -- the reader is
         * listing which credential objects it's configured to accept. */
        uint8_t lc = apdu[4];
        size_t end = 5 + lc;
        if(end > len) end = len;
        size_t i = 5;
        uint8_t new_this_time = 0;
        while(i + 1 < end) {
            uint8_t tag = apdu[i];
            uint8_t tlen = apdu[i + 1];
            if(i + 2 + tlen > end) break;
            if(tag == 0x06) {
                char oid_str[OID_STR_LEN];
                decode_oid(&apdu[i + 2], tlen, oid_str, sizeof(oid_str));
                if(state_add_oid(state, oid_str)) {
                    new_this_time++;
                    switch(classify_oid(&apdu[i + 2], tlen)) {
                    case OidKindStandard:
                        state->oid_standard_count++;
                        break;
                    case OidKindCustom:
                        state->oid_custom_count++;
                        break;
                    case OidKindOther:
                        state->oid_other_count++;
                        break;
                    }
                }
            }
            i += 2 + tlen;
        }
        if(new_this_time > 0) {
            snprintf(
                state->last_event,
                sizeof(state->last_event),
                "Found %u new credential object(s)",
                new_this_time);
        } else {
            snprintf(state->last_event, sizeof(state->last_event), "Credential list re-offered");
        }
        FURI_LOG_I(TAG, "%s (standard=%u custom=%u other=%u)", state->last_event,
                   state->oid_standard_count, state->oid_custom_count, state->oid_other_count);
    } else if(len >= 5 && apdu[1] == 0xA4) {
        /* SELECT AID: CLA INS P1 P2 Lc AID -- the reader is offering/probing
         * an application/mode (credential slot, admin mode, updater, ...). */
        uint8_t lc = apdu[4];
        size_t avail = len > 5 ? len - 5 : 0;
        if(lc > avail) lc = (uint8_t)avail;
        const char* name = classify_aid(&apdu[5], lc);
        char label[AID_STR_LEN];
        char english[48];
        if(name) {
            strncpy(label, name, sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
            strncpy(english, english_for_aid(name), sizeof(english) - 1);
            english[sizeof(english) - 1] = '\0';
            if(aid_is_admin_like(name)) state->admin_mode_seen = true;
        } else {
            size_t pos = 0;
            for(uint8_t k = 0; k < lc && pos + 2 < sizeof(label); k++) {
                pos += snprintf(label + pos, sizeof(label) - pos, "%02X", apdu[5 + k]);
            }
            /* Unrecognised AID: describe it by its RID (first 5 bytes) rather
             * than dumping the whole raw AID -- still plain English, just
             * honest about not knowing exactly what it is. */
            snprintf(english, sizeof(english), "Unrecognized app (RID %02X%02X%02X%02X%02X)",
                     lc > 0 ? apdu[5] : 0, lc > 1 ? apdu[6] : 0, lc > 2 ? apdu[7] : 0,
                     lc > 3 ? apdu[8] : 0, lc > 4 ? apdu[9] : 0);
            state->admin_mode_seen = true; /* unknown app -- treat as noteworthy */
        }
        bool is_new = state_add_aid(state, label, english);
        snprintf(state->last_event, sizeof(state->last_event), "%s", english);
        if(is_new) FURI_LOG_I(TAG, "New mode offered: %s (%s)", english, label);
    } else {
        /* Some other reader command -- describe it plainly on screen, log the
         * FULL APDU hex (not just the first 4 bytes) since these are exactly
         * the ones worth capturing precisely for later analysis. */
        uint8_t ins = len > 1 ? apdu[1] : 0;
        snprintf(state->last_event, sizeof(state->last_event), "Other reader command (ins=%02X)", ins);
        char hexbuf[3 * 64 + 1] = {0};
        size_t hp = 0;
        for(size_t i = 0; i < len && hp + 3 < sizeof(hexbuf); i++) {
            hp += snprintf(hexbuf + hp, sizeof(hexbuf) - hp, "%02X ", apdu[i]);
        }
        FURI_LOG_I(TAG, "Other command ins=%02X len=%u full=[ %s]", ins, (unsigned)len, hexbuf);
    }

    furi_mutex_release(app->mutex);
}

static NfcCommand hid_recon_nfc_callback(NfcGenericEvent event, void* context) {
    HidReconApp* app = context;
    furi_assert(event.protocol == NfcProtocolIso14443_4a);
    Iso14443_4aListenerEvent* iso_event = event.event_data;

    if(iso_event->type == Iso14443_4aListenerEventTypeReceivedData) {
        BitBuffer* rx = iso_event->data->buffer;
        size_t len = bit_buffer_get_size_bytes(rx);
        /* Copy off the stack before releasing control -- rx_buffer is owned
         * by the listener and must not be retained past this callback. */
        uint8_t apdu[64];
        size_t copy_len = len < sizeof(apdu) ? len : sizeof(apdu);
        for(size_t i = 0; i < copy_len; i++) apdu[i] = bit_buffer_get_byte(rx, i);

        handle_apdu(app, apdu, copy_len);

        bit_buffer_reset(app->tx_buffer);
#if FUZZ_MODE
        /* Cycle through malformed replies (fuzz_cases[]) instead of always
         * answering plain 9000 -- tests reader NFC-stack robustness the same
         * way hid_rm.fuzz already tested it over BLE. Config data is already
         * captured above regardless of which reply we send. */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        const FuzzCase* fc = &fuzz_cases[app->state.fuzz_index % FUZZ_CASE_COUNT];
        app->state.fuzz_index++;
        strncpy(app->state.fuzz_last_case, fc->name, sizeof(app->state.fuzz_last_case) - 1);
        app->state.fuzz_last_case[sizeof(app->state.fuzz_last_case) - 1] = '\0';
        furi_mutex_release(app->mutex);
        if(fc->len > 0) bit_buffer_copy_bytes(app->tx_buffer, fc->bytes, fc->len);
        FURI_LOG_I(TAG, "fuzz case -> %s (%u bytes)", fc->name, (unsigned)fc->len);
#else
        /* Always answer 9000 -- live-proven (PROTOCOL.md) that the reader
         * only checks the trailing status word, not the content. */
        uint8_t sw[] = {0x90, 0x00};
        bit_buffer_copy_bytes(app->tx_buffer, sw, sizeof(sw));
#endif
        iso14443_4a_listener_send_block((Iso14443_4aListener*)event.instance, app->tx_buffer);

        app->dirty = true;
    } else if(
        iso_event->type == Iso14443_4aListenerEventTypeHalted ||
        iso_event->type == Iso14443_4aListenerEventTypeFieldOff) {
        /* The reader's own idle-polling pulses its field on/off rapidly (observed:
         * every ~200ms) without ever completing RATS activation, so this branch
         * fires very often. Count every toggle (useful diagnostic: proves RF
         * coupling is happening) but only log/redraw on the FIRST transition
         * into "ended" and periodically thereafter, to avoid flooding the GUI
         * update queue (see HidReconApp.dirty) and the log. */
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        bool was_active = app->state.phase != PhaseEnded;
        app->state.phase = PhaseEnded;
        app->state.field_toggle_count++;
        bool should_log = was_active || (app->state.field_toggle_count % 25 == 0);
        if(should_log) {
            snprintf(
                app->state.last_event,
                sizeof(app->state.last_event),
                "Waiting for reader contact (%lu tries)",
                (unsigned long)app->state.field_toggle_count);
        }
        furi_mutex_release(app->mutex);
        if(should_log) {
            FURI_LOG_I(TAG, "%s", app->state.last_event);
            app->dirty = true;
        }
    }

    return NfcCommandContinue; /* stay armed for the next tap/session */
}

/* ---- GUI ---- */
static void draw_callback(Canvas* canvas, void* ctx) {
    HidReconApp* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    ReconState* state = &app->state;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "HID Reader Recon");
    canvas_draw_line(canvas, 0, 13, 127, 13);

    canvas_set_font(canvas, FontSecondary);
    const char* phase_str = state->phase == PhaseIdle    ? "Waiting for reader..." :
                             state->phase == PhaseActive ? "Active" :
                                                            "Session ended (tap to retry)";
    canvas_draw_str(canvas, 2, 23, phase_str);

    /* Plain-English summary of what was found -- no AID names/hex or raw
     * OIDs here; that detail is in the saved log for anyone who wants it. */
    char line[40];
    uint8_t total_creds = state->oid_standard_count + state->oid_custom_count + state->oid_other_count;
    if(total_creds > 0) {
        snprintf(line, sizeof(line), "Credentials: %u std, %u custom",
                 state->oid_standard_count, state->oid_custom_count);
    } else {
        snprintf(line, sizeof(line), "Credentials: none found yet");
    }
    canvas_draw_str(canvas, 2, 33, line);

#if FUZZ_MODE
    snprintf(line, sizeof(line), "Fuzz: %s", state->fuzz_last_case);
#else
    snprintf(line, sizeof(line), "Admin mode: %s", state->admin_mode_seen ? "seen" : "not seen");
#endif
    canvas_draw_str(canvas, 2, 43, line);

    canvas_draw_str(canvas, 2, 53, state->last_event);
    canvas_draw_line(canvas, 0, 55, 127, 55);
    canvas_draw_str(canvas, 2, 63, "OK: save report   Back: exit");

    furi_mutex_release(app->mutex);
}

static void input_callback(InputEvent* event, void* ctx) {
    HidReconApp* app = ctx;
    furi_message_queue_put(app->input_queue, event, 0);
}

/* ---- Save a human-readable session log (mirrors hid_rm.leak.render_text) ---- */
static void save_log(HidReconApp* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    ReconState snapshot = app->state;
    furi_mutex_release(app->mutex);

    storage_common_mkdir(app->storage, "/ext/apps_data/hid_recon");
    File* file = storage_file_alloc(app->storage);
    bool ok = storage_file_open(file, LOG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    if(ok) {
        char buf[200];
        uint8_t total_creds =
            snapshot.oid_standard_count + snapshot.oid_custom_count + snapshot.oid_other_count;

        /* --- Plain-English summary first: this is what most readers of the
         * log want, without needing to know what an OID or AID is. --- */
        int n = snprintf(
            buf,
            sizeof(buf),
            "HID Reader Recon -- plain-English summary\r\n"
            "===========================================\r\n\r\n"
            "Credential objects this reader is configured to accept: %u\r\n",
            total_creds);
        storage_file_write(file, buf, n);
        if(total_creds > 0) {
            n = snprintf(
                buf, sizeof(buf), "  - %u standard HID default credential(s)\r\n",
                snapshot.oid_standard_count);
            storage_file_write(file, buf, n);
            n = snprintf(
                buf, sizeof(buf), "  - %u non-standard / customer-specific credential object(s)\r\n",
                snapshot.oid_custom_count);
            storage_file_write(file, buf, n);
            if(snapshot.oid_other_count > 0) {
                n = snprintf(
                    buf, sizeof(buf), "  - %u unrecognised object(s)\r\n", snapshot.oid_other_count);
                storage_file_write(file, buf, n);
            }
        }
        n = snprintf(
            buf,
            sizeof(buf),
            "\r\nAdmin/management mode offered by the reader: %s\r\n\r\n",
            snapshot.admin_mode_seen ? "yes" : "not seen this session");
        storage_file_write(file, buf, n);
        n = snprintf(buf, sizeof(buf), "Modes the reader offered:\r\n");
        storage_file_write(file, buf, n);
        for(uint8_t i = 0; i < snapshot.aid_count; i++) {
            n = snprintf(buf, sizeof(buf), "  - %s\r\n", snapshot.aid_english[i]);
            storage_file_write(file, buf, n);
        }

        /* --- Credential technologies in HID Reader Manager's own vocabulary
         * (KeyType), mirroring hid_rm's technology report. What the
         * unauthenticated discovery loop proves vs. what stays behind the
         * SEOS-admin (mobile-key) auth wall. See MOBILE_KEYS.md. --- */
        n = snprintf(
            buf, sizeof(buf),
            "\r\nCredential technologies (Reader Manager KeyType terms):\r\n");
        storage_file_write(file, buf, n);
        if(total_creds > 0) {
            n = snprintf(
                buf, sizeof(buf),
                "  [x] Seos -- configured (SEOS/PACS credential objects seen)\r\n");
            storage_file_write(file, buf, n);
        }
        if(snapshot.admin_mode_seen) {
            n = snprintf(
                buf, sizeof(buf),
                "  [x] MobileAdmin -- reader expects a mobile admin card\r\n");
            storage_file_write(file, buf, n);
        }
        n = snprintf(
            buf, sizeof(buf),
            "\r\nMobile keys: %s\r\n",
            snapshot.admin_mode_seen ?
                "reader is configured to USE mobile keys (mobile admin card offered)." :
                "no mobile-key admin AID seen this session.");
        storage_file_write(file, buf, n);
        n = snprintf(
            buf, sizeof(buf),
            "Not determinable without an authenticated (mobile-key) read:\r\n"
            "  iCLASS/SE/SR, MIFARE DESFire EV1/EV3, Google/Apple/Samsung wallets\r\n");
        storage_file_write(file, buf, n);
        n = snprintf(
            buf, sizeof(buf),
            "  (the admin mobile key is cloud-issued & non-exportable; see MOBILE_KEYS.md)\r\n");
        storage_file_write(file, buf, n);

        n = snprintf(
            buf,
            sizeof(buf),
            "\r\n(No credentials, keys, or invite codes were used -- this reader answers this\r\n"
            "much to any NFC device that replies with a plain ISO7816 success code.)\r\n");
        storage_file_write(file, buf, n);

        /* --- Technical detail second, for anyone who wants to cross-check
         * against hid_rm's Python tooling or the raw protocol notes. --- */
        n = snprintf(
            buf,
            sizeof(buf),
            "\r\n-------------------------------------------\r\n"
            "Technical detail\r\n"
            "-------------------------------------------\r\n"
            "APDU exchanges: %lu\r\nField on/off toggles: %lu\r\n"
            "OIDs found: %u\r\nAIDs found: %u\r\n\r\n",
            (unsigned long)snapshot.exchange_count,
            (unsigned long)snapshot.field_toggle_count,
            snapshot.oid_count,
            snapshot.aid_count);
        storage_file_write(file, buf, n);
        for(uint8_t i = 0; i < snapshot.oid_count; i++) {
            /* oids[i] already holds the full dotted OID (decode_oid emits the
             * complete "1.3.6.1.4.1.29240...." string from the DER bytes). */
            n = snprintf(buf, sizeof(buf), "OID %u: %s\r\n", i + 1, snapshot.oids[i]);
            storage_file_write(file, buf, n);
        }
        for(uint8_t i = 0; i < snapshot.aid_count; i++) {
            n = snprintf(
                buf, sizeof(buf), "AID %u: %s  (%s)\r\n", i + 1, snapshot.aids[i],
                snapshot.aid_english[i]);
            storage_file_write(file, buf, n);
        }

        /* --- Raw reader-command transcript: every APDU the reader sent, full
         * hex. This is where the SEOS authenticated key exchange (AKE)
         * challenge lands once the reader believes a credential is present --
         * the bytes a real credential (or a key/SAM oracle) would have to
         * answer. Written from app (not the stack snapshot); listener is
         * already stopped by the time save_log runs, so no concurrent writer. */
        n = snprintf(
            buf, sizeof(buf),
            "\r\nRaw reader-command transcript (%u APDUs, reader->card):\r\n",
            app->transcript_apdu_count);
        storage_file_write(file, buf, n);
        if(app->transcript_len > 0) {
            storage_file_write(file, app->transcript, app->transcript_len);
        } else {
            n = snprintf(buf, sizeof(buf), "(none captured this session)\r\n");
            storage_file_write(file, buf, n);
        }

        FURI_LOG_I(TAG, "Saved log to %s", LOG_PATH);
    } else {
        FURI_LOG_W(TAG, "Failed to open %s for writing", LOG_PATH);
    }
    storage_file_close(file);
    storage_file_free(file);
}

int32_t hid_recon_app(void* p) {
    UNUSED(p);

    HidReconApp* app = malloc(sizeof(HidReconApp));
    memset(app, 0, sizeof(HidReconApp));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->state.phase = PhaseIdle;
    strncpy(app->state.last_event, "Ready.", sizeof(app->state.last_event) - 1);
    strncpy(app->state.fuzz_last_case, "(none yet)", sizeof(app->state.fuzz_last_case) - 1);

    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_callback, app);
    view_port_input_callback_set(app->view_port, input_callback, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    app->storage = furi_record_open(RECORD_STORAGE);

    /* Configure the emulated card as the STANDARD_SEOS credential
     * (Constants.AID.STANDARD_SEOS base, live-verified 16-byte on-wire form
     * -- see PROTOCOL.md). UID is random per session (not security-relevant
     * for this recon use case); SAK bit 0x20 marks ISO14443-4 compliance so
     * the reader attempts RATS/T=CL activation. */
    app->iso4a_data = iso14443_4a_alloc();
    Iso14443_3aData* iso3a = iso14443_4a_get_base_data(app->iso4a_data);
    uint8_t uid[4];
    furi_hal_random_fill_buf(uid, sizeof(uid));
    uid[0] = (uint8_t)((uid[0] & 0xFE) | 0x00); /* clear cascade-tag-like top bit pattern */
    iso14443_3a_set_uid(iso3a, uid, sizeof(uid));
    iso14443_3a_set_sak(iso3a, 0x20);
    uint8_t atqa[2] = {0x04, 0x00};
    iso14443_3a_set_atqa(iso3a, atqa);
    /* iso14443_4a_alloc()'s default ATS is TL=1 (empty body, no T0 byte at
     * all) -- spec-legal but some readers may not proceed past RATS with it.
     * Use a slightly fuller, still-generic ATS instead: T0 with FSCI=8
     * (256-byte frames), no TA1/TB1/TC1, plus 2 historical bytes. */
    uint8_t hist[2] = {0x80, 0x31};
    simple_array_init(app->iso4a_data->ats_data.t1_tk, sizeof(hist));
    memcpy(simple_array_get_data(app->iso4a_data->ats_data.t1_tk), hist, sizeof(hist));
    app->iso4a_data->ats_data.t0 = 0x08; /* FSCI=8, no TA1/TB1/TC1 */
    app->iso4a_data->ats_data.tl = 1 + 1 + sizeof(hist); /* TL + T0 + historical bytes */

    app->tx_buffer = bit_buffer_alloc(256);
    app->nfc = nfc_alloc();
    app->listener =
        nfc_listener_alloc(app->nfc, NfcProtocolIso14443_4a, (const NfcDeviceData*)app->iso4a_data);
    nfc_listener_start(app->listener, hid_recon_nfc_callback, app);
    FURI_LOG_I(TAG, "Listener started, emulating STANDARD_SEOS");

    app->running = true;
    uint32_t start_tick = furi_get_tick();
    InputEvent event;
    while(app->running) {
        if(furi_message_queue_get(app->input_queue, &event, 100) == FuriStatusOk) {
            FURI_LOG_I(TAG, "input key=%d type=%d", event.key, event.type);
            if(event.type == InputTypeShort) {
                if(event.key == InputKeyBack) {
                    app->running = false;
                } else if(event.key == InputKeyOk) {
                    save_log(app);
                    furi_mutex_acquire(app->mutex, FuriWaitForever);
                    strncpy(app->state.last_event, "Saved to hid_recon/session.txt",
                            sizeof(app->state.last_event) - 1);
                    furi_mutex_release(app->mutex);
                    app->dirty = true;
                }
            }
        }
        if(furi_get_tick() - start_tick > AUTO_EXIT_MS) {
            FURI_LOG_I(TAG, "Auto-exit timeout reached");
            app->running = false;
        }
        /* Redraw at most ~10Hz here, driven by the main loop only -- the NFC
         * callback thread just sets app->dirty rather than calling
         * view_port_update() itself, since it can fire much faster than the
         * GUI can keep up with (observed: reader field toggles ~5x/sec). */
        if(app->dirty) {
            app->dirty = false;
            view_port_update(app->view_port);
        }
    }
    view_port_update(app->view_port); /* final draw so "Auto-exit..." is visible briefly */

    FURI_LOG_I(TAG, "Stopping NFC listener...");
    nfc_listener_stop(app->listener);
    FURI_LOG_I(TAG, "Listener stopped, freeing...");
    nfc_listener_free(app->listener);
    nfc_free(app->nfc);
    iso14443_4a_free(app->iso4a_data);
    bit_buffer_free(app->tx_buffer);
    FURI_LOG_I(TAG, "NFC resources freed, saving final log and exiting");
    save_log(app);

    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_STORAGE);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
