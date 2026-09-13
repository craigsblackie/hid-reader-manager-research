/*
 * HID Locate Reader -- Flipper Zero app ("find my reader")
 * ========================================================
 *
 * Sends the HID Reader Manager "reader locate" command (Artemis
 * CoreCommand.readerLocate, tag 36) to an HID Signo/iCLASS SE reader over BLE,
 * making it flash its LED and beep so you can find it. This is the same
 * unauthenticated command implemented on the PC side in the companion `hid_rm`
 * Python tool; see PROTOCOL.md sec 19 in the research repo.
 *
 * WHY THIS APP IS UNUSUAL
 * -----------------------
 * "Locate" requires the Flipper to act as a BLE *central* (GATT client):
 * connect out to the reader, find its command characteristic, and write to it.
 * Stock/Momentum Flipper firmware exposes NO central-role capability to apps --
 * every aci_gap_ / aci_gatt_ function, and even the raw hci_send_req transport,
 * is absent from the app-accessible SDK symbol table (verified exhaustively).
 * The ONLY way to do this without rebuilding firmware is to call the firmware's
 * internal hci_send_req() by its absolute flash address and re-implement the
 * few ACI/HCI command wrappers (which are just parameter-packers on top of it)
 * ourselves. Command/response serialization is handled *inside* hci_send_req
 * (it acquires the OS's hci mutex via its status callback), so calling it from
 * our app thread is automatically mutually-exclusive with the OS's own BLE
 * traffic -- this is what makes the approach safe rather than merely possible.
 *
 * SAFETY GATE (important)
 * -----------------------
 * The hci_send_req address is specific to one exact firmware build. This app is
 * pinned to Momentum mntm-012 (commit e1784e74), where hci_send_req lives at
 * 0x0801b8ac. Before making ANY raw call, the app reads the first 16 bytes at
 * that address (flash is memory-mapped/readable) and compares them to the known
 * function prologue from that build. If they don't match -- i.e. you're running
 * any other firmware -- the app refuses to run and does nothing. This makes a
 * version mismatch a harmless "unsupported firmware" screen instead of a jump
 * to a garbage address (hardfault). To support another build, add its address
 * + prologue to the table below.
 *
 * Live testing is against a reader you own / are authorised to test.
 */

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <furi_ble/event_dispatcher.h>

#define TAG "HidLocate"

/* ------------------------------------------------------------------------- */
/* Firmware-pinned raw entry point + self-verifying safety gate              */
/* ------------------------------------------------------------------------- */

/* hci_send_req: Thumb call address (odd) and code start (even) for mntm-012. */
#define HCI_SEND_REQ_CALL 0x0801b8adUL
#define HCI_SEND_REQ_CODE 0x0801b8acUL

/* First 16 bytes of hci_send_req() as built in Momentum mntm-012 (e1784e74).
 * Extracted from that release's firmware.elf; used only to confirm the code at
 * HCI_SEND_REQ_CODE really is that function before we ever jump to it. */
static const uint8_t k_hci_send_req_prologue[16] = {
    0x2d, 0xe9, 0xf7, 0x43, 0x2e, 0x4e, 0x33, 0x68,
    0x04, 0x46, 0x0b, 0xb1, 0x00, 0x20, 0x98, 0x47};

typedef int (*hci_send_req_fn)(void* req, uint8_t async);

static bool hid_locate_fw_supported(void) {
    return memcmp((const void*)HCI_SEND_REQ_CODE, k_hci_send_req_prologue, 16) == 0;
}

/* struct hci_request, matching the copro ABI (ble_const.h). */
typedef struct {
    uint16_t ogf;
    uint16_t ocf;
    int event;
    void* cparam;
    int clen;
    void* rparam;
    int rlen;
} hci_request_t;

static uint8_t hid_locate_send(uint16_t ogf, uint16_t ocf, const uint8_t* cparam, int clen) {
    uint8_t status = 0xFF;
    hci_request_t rq = {
        .ogf = ogf,
        .ocf = ocf,
        .event = 0x0F,
        .cparam = (void*)cparam,
        .clen = clen,
        .rparam = &status,
        .rlen = 1,
    };
    hci_send_req_fn fn = (hci_send_req_fn)HCI_SEND_REQ_CALL;
    if(fn(&rq, 0) < 0) return 0xFE; /* transport timeout */
    return status;
}

/* ------------------------------------------------------------------------- */
/* Reimplemented ACI/HCI command wrappers (param-packers over hci_send_req)  */
/* ------------------------------------------------------------------------- */

static void put16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

/* HCI LE Create Connection (OGF 0x08, OCF 0x00d) -- raw HCI, so no GAP
 * central-role init is needed; GATT-client ops work on the resulting handle. */
static uint8_t hid_locate_le_create_connection(const uint8_t peer_addr_le[6], uint8_t peer_addr_type) {
    uint8_t p[25];
    int i = 0;
    put16(&p[i], 0x0060); i += 2; /* LE_Scan_Interval ~60ms */
    put16(&p[i], 0x0030); i += 2; /* LE_Scan_Window ~30ms */
    p[i++] = 0x00; /* Initiator_Filter_Policy: use peer address */
    p[i++] = peer_addr_type; /* 0=public */
    memcpy(&p[i], peer_addr_le, 6); i += 6;
    p[i++] = 0x00; /* Own_Address_Type: public */
    put16(&p[i], 0x0018); i += 2; /* Conn_Interval_Min ~30ms */
    put16(&p[i], 0x0028); i += 2; /* Conn_Interval_Max ~50ms */
    put16(&p[i], 0x0000); i += 2; /* Conn_Latency */
    put16(&p[i], 0x01F4); i += 2; /* Supervision_Timeout ~5s */
    put16(&p[i], 0x0000); i += 2; /* Min_CE_Length */
    put16(&p[i], 0x0000); i += 2; /* Max_CE_Length */
    return hid_locate_send(0x08, 0x00d, p, i);
}

/* ACI GAP Create Connection (OGF 0x3f, OCF 0x9c) -- the vendor GAP-layer
 * connect. Unlike raw HCI LE Create Connection (which the ST 5.x stack rejected
 * with "unknown command"), this is the abstraction the stack actually exposes;
 * it internally issues whichever underlying HCI command the stack supports. */
static uint8_t hid_locate_gap_create_connection(const uint8_t peer_addr_le[6], uint8_t peer_addr_type) {
    uint8_t p[24];
    int i = 0;
    put16(&p[i], 0x0060); i += 2; /* LE_Scan_Interval */
    put16(&p[i], 0x0030); i += 2; /* LE_Scan_Window */
    p[i++] = peer_addr_type;
    memcpy(&p[i], peer_addr_le, 6); i += 6;
    p[i++] = 0x00; /* Own_Address_Type: public */
    put16(&p[i], 0x0018); i += 2; /* Conn_Interval_Min */
    put16(&p[i], 0x0028); i += 2; /* Conn_Interval_Max */
    put16(&p[i], 0x0000); i += 2; /* Conn_Latency */
    put16(&p[i], 0x01F4); i += 2; /* Supervision_Timeout */
    put16(&p[i], 0x0000); i += 2; /* Min_CE_Length */
    put16(&p[i], 0x0000); i += 2; /* Max_CE_Length */
    return hid_locate_send(0x3f, 0x09c, p, i);
}

/* HCI LE Create Connection Cancel (OGF 0x08, OCF 0x00e) -- abort a pending,
 * not-yet-completed connection attempt so the controller stops scanning. */
static uint8_t hid_locate_le_create_connection_cancel(void) {
    return hid_locate_send(0x08, 0x00e, NULL, 0);
}

/* ACI GATT Discover Characteristic by UUID (OGF 0x3f, OCF 0x116). */
static uint8_t hid_locate_disc_char_by_uuid(
    uint16_t conn_handle,
    const uint8_t uuid128_le[16]) {
    uint8_t p[23];
    int i = 0;
    put16(&p[i], conn_handle); i += 2;
    put16(&p[i], 0x0001); i += 2; /* Start_Handle */
    put16(&p[i], 0xFFFF); i += 2; /* End_Handle */
    p[i++] = 0x02; /* UUID_Type: 128-bit */
    memcpy(&p[i], uuid128_le, 16); i += 16;
    return hid_locate_send(0x3f, 0x116, p, i);
}

/* ACI GATT Write Without Response (OGF 0x3f, OCF 0x123). */
static uint8_t hid_locate_write_without_resp(
    uint16_t conn_handle,
    uint16_t attr_handle,
    const uint8_t* val,
    uint8_t val_len) {
    uint8_t p[5 + 244];
    int i = 0;
    put16(&p[i], conn_handle); i += 2;
    put16(&p[i], attr_handle); i += 2;
    p[i++] = val_len;
    memcpy(&p[i], val, val_len); i += val_len;
    return hid_locate_send(0x3f, 0x123, p, i);
}

/* HCI Disconnect (OGF 0x01, OCF 0x006). */
static uint8_t hid_locate_disconnect(uint16_t conn_handle, uint8_t reason) {
    uint8_t p[3];
    put16(&p[0], conn_handle);
    p[2] = reason;
    return hid_locate_send(0x01, 0x006, p, 3);
}

/* ------------------------------------------------------------------------- */
/* CRC16 + Artemis framing + BLE fragmentation (ported from hid_rm)           */
/* ------------------------------------------------------------------------- */

static uint16_t crc16_tbl[256];
static bool crc16_ready = false;

static void crc16_init(void) {
    if(crc16_ready) return;
    for(uint32_t b = 0; b < 256; b++) {
        uint32_t c = b;
        for(uint32_t k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0x8408 : (c >> 1);
        crc16_tbl[b] = (uint16_t)c;
    }
    crc16_ready = true;
}

static uint16_t crc16_calc(const uint8_t* d, size_t n) {
    crc16_init();
    uint16_t crc = 0;
    for(size_t i = 0; i < n; i++) crc = (crc >> 8) ^ crc16_tbl[(crc ^ d[i]) & 0xFF];
    return crc;
}

/* Wrap an Artemis payload as APDU (00 CA 00 00 Lc <payload>) then frame it as
 * [u16 len BE][apdu][u16 crc]. Returns framed length; out must be big enough. */
static size_t hid_locate_frame(const uint8_t* payload, size_t plen, uint8_t* out) {
    uint8_t apdu[5 + 255];
    apdu[0] = 0x00; /* CLA */
    apdu[1] = 0xCA; /* INS = GET_DATA (as used by hid_rm) */
    apdu[2] = 0x00; /* P1 */
    apdu[3] = 0x00; /* P2 */
    apdu[4] = (uint8_t)plen; /* Lc */
    memcpy(&apdu[5], payload, plen);
    size_t apdu_len = 5 + plen;

    out[0] = (uint8_t)((apdu_len >> 8) & 0xFF);
    out[1] = (uint8_t)(apdu_len & 0xFF);
    memcpy(&out[2], apdu, apdu_len);
    uint16_t crc = crc16_calc(out, apdu_len + 2);
    uint16_t sw = (uint16_t)((crc << 8) | (crc >> 8));
    out[apdu_len + 2] = (uint8_t)(sw & 0xFF);
    out[apdu_len + 3] = (uint8_t)((sw >> 8) & 0xFF);
    return apdu_len + 4;
}

#define FRAG_PAYLOAD 19

/* ------------------------------------------------------------------------- */
/* BLE event handling                                                        */
/* ------------------------------------------------------------------------- */

#define EVT_CONNECTED    (1UL << 0)
#define EVT_CONN_FAILED  (1UL << 1)
#define EVT_DISCONNECTED (1UL << 2)
#define EVT_CHAR_FOUND   (1UL << 3)
#define EVT_DISC_DONE    (1UL << 4)

/* Minimal packed views of the copro event structs (stable wire ABI). */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t data[];
} uart_pckt_t;
typedef struct __attribute__((packed)) {
    uint8_t evt;
    uint8_t plen;
    uint8_t data[];
} event_pckt_t;

#define HCI_DISCONNECTION_COMPLETE 0x05
#define HCI_LE_META 0x3E
#define HCI_VENDOR_SPECIFIC 0xFF
#define SUB_LE_CONN_COMPLETE 0x01
#define SUB_LE_ENH_CONN_COMPLETE 0x0A
#define VS_ATT_READ_BY_TYPE_RESP 0x0C06
#define VS_GATT_PROC_COMPLETE 0x0C10

typedef struct {
    FuriEventFlag* flags;
    GapSvcEventHandler* handler;
    bool connected;
    uint16_t conn_handle;
    bool char_found;
    uint16_t char_value_handle;
} BleCtx;

static BleEventAckStatus hid_locate_event_handler(void* event, void* context) {
    BleCtx* ctx = context;
    event_pckt_t* evt = (event_pckt_t*)(((uart_pckt_t*)event)->data);
    BleEventAckStatus ret = BleEventNotAck;

    if(evt->evt == HCI_LE_META) {
        uint8_t sub = evt->data[0];
        if(sub == SUB_LE_CONN_COMPLETE || sub == SUB_LE_ENH_CONN_COMPLETE) {
            /* rp0: Status(1) Connection_Handle(2) Role(1) ... after subevent byte */
            uint8_t status = evt->data[1];
            uint16_t handle = (uint16_t)evt->data[2] | ((uint16_t)evt->data[3] << 8);
            uint8_t role = evt->data[4];
            if(role == 0x00) { /* we are master/central: this is our connection */
                if(status == 0x00) {
                    ctx->connected = true;
                    ctx->conn_handle = handle;
                    furi_event_flag_set(ctx->flags, EVT_CONNECTED);
                } else {
                    furi_event_flag_set(ctx->flags, EVT_CONN_FAILED);
                }
                ret = BleEventAckFlowEnable; /* stop gap.c from treating it as peripheral */
            }
        }
    } else if(evt->evt == HCI_DISCONNECTION_COMPLETE) {
        /* Status(1) Connection_Handle(2) Reason(1) */
        uint16_t handle = (uint16_t)evt->data[1] | ((uint16_t)evt->data[2] << 8);
        if(ctx->connected && handle == ctx->conn_handle) {
            ctx->connected = false;
            furi_event_flag_set(ctx->flags, EVT_DISCONNECTED);
            /* return NotAck so gap.c still runs its advertising-restart housekeeping */
        }
    } else if(evt->evt == HCI_VENDOR_SPECIFIC) {
        uint16_t ecode = (uint16_t)evt->data[0] | ((uint16_t)evt->data[1] << 8);
        const uint8_t* d = &evt->data[2];
        if(ecode == VS_ATT_READ_BY_TYPE_RESP && !ctx->char_found) {
            /* Connection_Handle(2) Handle_Value_Pair_Length(1) Data_Length(1) pairs... */
            uint8_t pair_len = d[2];
            const uint8_t* pair = &d[4];
            /* pair = [decl_handle(2), properties(1), value_handle(2), uuid...] */
            if(pair_len >= 5) {
                ctx->char_value_handle = (uint16_t)pair[3] | ((uint16_t)pair[4] << 8);
                ctx->char_found = true;
                furi_event_flag_set(ctx->flags, EVT_CHAR_FOUND);
            }
            ret = BleEventAckFlowEnable;
        } else if(ecode == VS_GATT_PROC_COMPLETE) {
            furi_event_flag_set(ctx->flags, EVT_DISC_DONE);
            ret = BleEventAckFlowEnable;
        }
    }
    return ret;
}

/* ------------------------------------------------------------------------- */
/* Locate sequence                                                           */
/* ------------------------------------------------------------------------- */

static const uint8_t k_reader_mac_le[6] = {0x31, 0x2b, 0x15, 0x33, 0x60, 0xc0}; /* C0:60:33:15:2B:31 */
static const uint8_t k_char_uuid_le[16] =
    {0x02, 0x00, 0x00, 0x7a, 0x17, 0x00, 0x00, 0x80,
     0x00, 0x10, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00}; /* 0000aa00-...-00177a000002 */

/* Locate presets: raw Artemis readerLocate payloads (validated byte-for-byte
 * against the vendor's own BinaryNotes.NET encoder; see hid_rm/artemis.py). */
typedef struct {
    const char* name;
    const uint8_t* payload;
    uint8_t len;
} LocatePreset;

static const uint8_t k_blue_3s[] = {
    0xa5, 0x25, 0xbf, 0x24, 0x22, 0xa0, 0x12, 0x80, 0x02, 0x0b, 0xb8, 0x81, 0x02, 0x01, 0x2c,
    0x82, 0x02, 0x01, 0x2c, 0x83, 0x01, 0x04, 0x84, 0x01, 0x00, 0xa1, 0x0c, 0x80, 0x02, 0x0b,
    0xb8, 0x81, 0x02, 0x00, 0xc8, 0x82, 0x02, 0x00, 0xc8};
static const uint8_t k_green_3s[] = {
    0xa5, 0x25, 0xbf, 0x24, 0x22, 0xa0, 0x12, 0x80, 0x02, 0x0b, 0xb8, 0x81, 0x02, 0x01, 0x2c,
    0x82, 0x02, 0x01, 0x2c, 0x83, 0x01, 0x02, 0x84, 0x01, 0x00, 0xa1, 0x0c, 0x80, 0x02, 0x0b,
    0xb8, 0x81, 0x02, 0x00, 0xc8, 0x82, 0x02, 0x00, 0xc8};
static const uint8_t k_red_5s[] = {
    0xa5, 0x25, 0xbf, 0x24, 0x22, 0xa0, 0x12, 0x80, 0x02, 0x13, 0x88, 0x81, 0x02, 0x01, 0x2c,
    0x82, 0x02, 0x01, 0x2c, 0x83, 0x01, 0x01, 0x84, 0x01, 0x00, 0xa1, 0x0c, 0x80, 0x02, 0x13,
    0x88, 0x81, 0x02, 0x00, 0xc8, 0x82, 0x02, 0x00, 0xc8};
static const uint8_t k_white_3s_silent[] = {
    0xa5, 0x17, 0xbf, 0x24, 0x14, 0xa0, 0x12, 0x80, 0x02, 0x0b, 0xb8, 0x81, 0x02, 0x01, 0x2c,
    0x82, 0x02, 0x01, 0x2c, 0x83, 0x01, 0x07, 0x84, 0x01, 0x00};

static const LocatePreset k_presets[] = {
    {"Blue 3s + beep", k_blue_3s, sizeof(k_blue_3s)},
    {"Green 3s + beep", k_green_3s, sizeof(k_green_3s)},
    {"Red 5s + beep", k_red_5s, sizeof(k_red_5s)},
    {"White 3s silent", k_white_3s_silent, sizeof(k_white_3s_silent)},
};
#define N_PRESETS (sizeof(k_presets) / sizeof(k_presets[0]))

typedef enum {
    ResultIdle,
    ResultConnecting,
    ResultDiscovering,
    ResultWriting,
    ResultDone,
    ResultFailConnect,
    ResultFailDiscover,
    ResultFailWrite,
} LocateResult;

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    FuriMessageQueue* input_queue;
    BleCtx ble;
    uint8_t preset_idx;
    LocateResult result;
    volatile bool running;
    volatile bool exit;
    char trace[512];
    size_t trace_len;
} App;

static void trace_reset(App* app) {
    app->trace[0] = 0;
    app->trace_len = 0;
}

static void trace_add(App* app, const char* fmt, ...) {
    if(app->trace_len >= sizeof(app->trace) - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(
        app->trace + app->trace_len, sizeof(app->trace) - app->trace_len, fmt, ap);
    va_end(ap);
    if(n > 0) app->trace_len += (size_t)n;
}

static void save_result(App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, "/ext/apps_data");
    storage_common_mkdir(storage, "/ext/apps_data/hid_locate");
    File* f = storage_file_alloc(storage);
    if(storage_file_open(
           f, "/ext/apps_data/hid_locate/last_run.txt", FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_write(f, app->trace, app->trace_len);
        storage_file_close(f);
    }
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

static const char* result_str(LocateResult r) {
    switch(r) {
    case ResultIdle: return "Ready";
    case ResultConnecting: return "Connecting...";
    case ResultDiscovering: return "Finding characteristic...";
    case ResultWriting: return "Sending locate...";
    case ResultDone: return "Done - reader located";
    case ResultFailConnect: return "FAILED: connect";
    case ResultFailDiscover: return "FAILED: characteristic";
    case ResultFailWrite: return "FAILED: write";
    default: return "?";
    }
}

/* Write a framed message split into ProtocolV1 BLE fragments. */
static bool hid_locate_write_frame(App* app, const uint8_t* frame, size_t frame_len) {
    if(frame_len <= FRAG_PAYLOAD) {
        uint8_t buf[1 + FRAG_PAYLOAD];
        buf[0] = 0xC0; /* single */
        memcpy(&buf[1], frame, frame_len);
        return hid_locate_write_without_resp(
                   app->ble.conn_handle, app->ble.char_value_handle, buf, (uint8_t)(frame_len + 1)) ==
               0x00;
    }
    size_t n = (frame_len + FRAG_PAYLOAD - 1) / FRAG_PAYLOAD;
    for(size_t idx = 0; idx < n; idx++) {
        size_t off = idx * FRAG_PAYLOAD;
        size_t clen = frame_len - off;
        if(clen > FRAG_PAYLOAD) clen = FRAG_PAYLOAD;
        uint8_t hdr;
        if(idx == 0)
            hdr = 0x80 | (uint8_t)((n - 1) > 31 ? 31 : (n - 1));
        else if(idx == n - 1)
            hdr = 0x40;
        else
            hdr = (uint8_t)((n - 1 - idx) & 0x1F);
        uint8_t buf[1 + FRAG_PAYLOAD];
        buf[0] = hdr;
        memcpy(&buf[1], &frame[off], clen);
        if(hid_locate_write_without_resp(
               app->ble.conn_handle, app->ble.char_value_handle, buf, (uint8_t)(clen + 1)) != 0x00)
            return false;
        furi_delay_ms(15); /* small gap between fragments */
    }
    return true;
}

static bool g_fw_supported = false;
static bool g_central_supported = false; /* Full BLE stack (central role) present */

static void hid_locate_run(App* app) {
    app->running = true;
    BleCtx* ble = &app->ble;
    ble->connected = false;
    ble->char_found = false;
    ble->conn_handle = 0;
    furi_event_flag_clear(
        ble->flags,
        EVT_CONNECTED | EVT_CONN_FAILED | EVT_DISCONNECTED | EVT_CHAR_FOUND | EVT_DISC_DONE);

    trace_reset(app);
    trace_add(app, "HID Locate run\n");
    trace_add(app, "fw_gate=%s\n", g_fw_supported ? "OK(mntm-012)" : "MISMATCH");
    trace_add(app, "radio_stack=%d (1=Light 2=Full)\n", (int)furi_hal_bt_get_radio_stack());
    trace_add(app, "preset=%s\n", k_presets[app->preset_idx].name);

    /* Plumbing sanity probe: hci_le_rand (OGF 0x08/OCF 0x018) is supported by
     * every ST BLE stack build. If this returns 0x00 our raw hci_send_req path
     * works, so a 0x01 on the connect commands below is specifically the Light
     * stack lacking the central role -- not a bug in our calling convention. */
    uint8_t rnd_st = hid_locate_send(0x08, 0x018, NULL, 0);
    trace_add(app, "probe hci_le_rand status=0x%02X\n", rnd_st);

    ble->handler = ble_event_dispatcher_register_svc_handler(hid_locate_event_handler, ble);

    app->result = ResultConnecting;
    view_port_update(app->view_port);

    /* Try the vendor GAP-layer connect first; fall back to raw HCI legacy. */
    uint8_t st = hid_locate_gap_create_connection(k_reader_mac_le, 0x00);
    trace_add(app, "gap_create_connection cmd_status=0x%02X\n", st);
    if(st != 0x00) {
        uint8_t st2 = hid_locate_le_create_connection(k_reader_mac_le, 0x00);
        trace_add(app, "hci_le_create_connection cmd_status=0x%02X\n", st2);
        st = st2;
    }
    if(st != 0x00) {
        FURI_LOG_E(TAG, "create_connection cmd status 0x%02X", st);
        app->result = ResultFailConnect;
        goto cleanup;
    }
    uint32_t f = furi_event_flag_wait(
        ble->flags, EVT_CONNECTED | EVT_CONN_FAILED, FuriFlagWaitAny, 8000);
    trace_add(app, "connect_wait flags=0x%08lX\n", (unsigned long)f);
    if((f & FuriFlagError) || !(f & EVT_CONNECTED)) {
        FURI_LOG_E(TAG, "connect failed/timeout");
        trace_add(app, "connect FAILED/timeout\n");
        /* abort the still-pending connection attempt so the controller stops
         * scanning in the background */
        hid_locate_le_create_connection_cancel();
        app->result = ResultFailConnect;
        goto cleanup;
    }
    trace_add(app, "connected handle=0x%04X\n", ble->conn_handle);

    app->result = ResultDiscovering;
    view_port_update(app->view_port);

    furi_event_flag_clear(ble->flags, EVT_CHAR_FOUND | EVT_DISC_DONE);
    st = hid_locate_disc_char_by_uuid(ble->conn_handle, k_char_uuid_le);
    trace_add(app, "disc_char cmd_status=0x%02X\n", st);
    if(st != 0x00) {
        FURI_LOG_E(TAG, "disc_char cmd status 0x%02X", st);
        app->result = ResultFailDiscover;
        goto disconnect;
    }
    f = furi_event_flag_wait(ble->flags, EVT_CHAR_FOUND | EVT_DISC_DONE, FuriFlagWaitAny, 5000);
    trace_add(app, "disc_wait flags=0x%08lX found=%d vhandle=0x%04X\n",
        (unsigned long)f, ble->char_found ? 1 : 0, ble->char_value_handle);
    if((f & FuriFlagError) || !ble->char_found) {
        FURI_LOG_E(TAG, "characteristic not found");
        app->result = ResultFailDiscover;
        goto disconnect;
    }

    app->result = ResultWriting;
    view_port_update(app->view_port);

    {
        const LocatePreset* preset = &k_presets[app->preset_idx];
        uint8_t frame[64];
        size_t frame_len = hid_locate_frame(preset->payload, preset->len, frame);
        bool wok = hid_locate_write_frame(app, frame, frame_len);
        trace_add(app, "write frame_len=%u ok=%d\n", (unsigned)frame_len, wok ? 1 : 0);
        app->result = wok ? ResultDone : ResultFailWrite;
    }

disconnect:
    hid_locate_disconnect(ble->conn_handle, 0x13); /* remote user terminated */
    furi_event_flag_wait(ble->flags, EVT_DISCONNECTED, FuriFlagWaitAny, 2000);
cleanup:
    if(ble->handler) {
        ble_event_dispatcher_unregister_svc_handler(ble->handler);
        ble->handler = NULL;
    }
    trace_add(app, "result=%s\n", result_str(app->result));
    save_result(app);
    app->running = false;
    view_port_update(app->view_port);
}

/* ------------------------------------------------------------------------- */
/* GUI                                                                       */
/* ------------------------------------------------------------------------- */

static void draw_callback(Canvas* canvas, void* context) {
    App* app = context;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 11, "HID Locate Reader");
    canvas_draw_line(canvas, 0, 14, 128, 14);
    canvas_set_font(canvas, FontSecondary);

    if(!g_fw_supported) {
        canvas_draw_str(canvas, 2, 28, "Unsupported firmware.");
        canvas_draw_str(canvas, 2, 40, "Needs Momentum mntm-012.");
        canvas_draw_str(canvas, 2, 52, "See app source to add a");
        canvas_draw_str(canvas, 2, 62, "build. Back to exit.");
        return;
    }

    if(!g_central_supported) {
        canvas_draw_str(canvas, 2, 26, "BLE Light stack: no");
        canvas_draw_str(canvas, 2, 36, "central role. Cannot");
        canvas_draw_str(canvas, 2, 46, "connect out to a reader.");
        canvas_draw_str(canvas, 2, 60, "Needs Full BLE stack. Back");
        return;
    }

    char line[48];
    snprintf(line, sizeof(line), "Reader C0:60:33:15:2B:31");
    canvas_draw_str(canvas, 2, 26, line);

    snprintf(line, sizeof(line), "Pattern: %s", k_presets[app->preset_idx].name);
    canvas_draw_str(canvas, 2, 38, line);

    canvas_draw_str(canvas, 2, 50, result_str(app->result));

    canvas_set_font(canvas, FontSecondary);
    if(app->running) {
        canvas_draw_str(canvas, 2, 62, "Working...");
    } else {
        canvas_draw_str(canvas, 2, 62, "OK=locate  Up/Dn=pattern");
    }
}

static void input_callback(InputEvent* input_event, void* context) {
    App* app = context;
    furi_message_queue_put(app->input_queue, input_event, FuriWaitForever);
}

int32_t hid_locate_app(void* p) {
    UNUSED(p);
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));
    app->result = ResultIdle;
    app->ble.flags = furi_event_flag_alloc();
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));

    g_fw_supported = hid_locate_fw_supported();
    if(!g_fw_supported) {
        FURI_LOG_E(TAG, "Unsupported firmware: hci_send_req prologue mismatch");
    }
    /* Central role lives in the co-processor BLE stack. Flipper's default Light
     * stack is peripheral-only, so connecting out to a reader is impossible
     * regardless of this app (confirmed live: connect commands return 0x01
     * "unknown", while a generic hci_le_rand returns 0x00). Only the Full stack
     * exposes the initiator. */
    g_central_supported = (furi_hal_bt_get_radio_stack() == FuriHalBtStackFull);
    if(!g_central_supported) {
        FURI_LOG_W(TAG, "BLE Light stack: central role unavailable");
    }

    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_callback, app);
    view_port_input_callback_set(app->view_port, input_callback, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    InputEvent event;
    bool running = true;
    while(running) {
        if(furi_message_queue_get(app->input_queue, &event, FuriWaitForever) != FuriStatusOk)
            continue;
        if(event.type != InputTypeShort && event.type != InputTypeRepeat) continue;

        if(event.key == InputKeyBack) {
            running = false;
        } else if(!g_fw_supported || !g_central_supported) {
            /* only Back does anything on the unsupported / Light-stack screen */
        } else if(app->running) {
            /* ignore input while a locate is in progress */
        } else if(event.key == InputKeyUp) {
            app->preset_idx = (app->preset_idx + N_PRESETS - 1) % N_PRESETS;
            view_port_update(app->view_port);
        } else if(event.key == InputKeyDown) {
            app->preset_idx = (app->preset_idx + 1) % N_PRESETS;
            view_port_update(app->view_port);
        } else if(event.key == InputKeyOk) {
            hid_locate_run(app);
        }
    }

    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    furi_event_flag_free(app->ble.flags);
    free(app);
    return 0;
}
