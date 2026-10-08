/* Pure helpers shared by the engine and the host tests. */
#ifndef SHARE_SUPPORT_H
#define SHARE_SUPPORT_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* `mov wN,#0x3fc` or `orr wN,wzr,#0x3fc`: the hotspot's RESET state (1020). */
static int share_reset_load(uint32_t ins, int *rn) {
    if ((ins & 0xffffffe0u) == 0x52807f80u || (ins & 0xffffffe0u) == 0x321e1fe0u) {
        *rn = ins & 31;
        return 1;
    }
    return 0;
}

/* The state gate: `csel wD, wRESET, w0, cond` right after the RESET load.
 * Rewriting it to `mov wD, w0` keeps the requested state. */
static unsigned share_patch_sites(const uint32_t *w, size_t count, size_t *site, int *destination) {
    unsigned found = 0;
    for (size_t i = 1; i < count; i++) {
        uint32_t ins = w[i];
        int loaded;
        if ((ins & 0x7fe00c00u) != 0x1a800000u || ((ins >> 16) & 31) != 0) continue;
        if (!share_reset_load(w[i - 1], &loaded) || loaded != (int)((ins >> 5) & 31)) continue;
        *site = i;
        *destination = ins & 31;
        found++;
    }
    return found;
}

static uint32_t share_patched_instruction(int destination) {
    return 0x2a0003e0u | (uint32_t)destination;
}

/* iOS 14's second gate: misd leaves RESET (1020) for AUTH_UNKNOWN (1021) only
 * when a client asked for authorization, and the carrier's answer then moves
 * it to OFF (1022). Wi-Fi-only models have no client and no carrier.
 *   and  wD, wAVAILABLE, wREQUESTED
 *   tst  wD, wC
 *   mov  wX, #0x3fc
 *   cinc wY, wX, ne
 * The rewrite drops the request and lands on OFF when tethering is available:
 *   ands wD, wAVAILABLE, wC
 *   mov  wX, #0x3fc
 *   add  wY, wX, wD, lsl #1
 *   nop */
static unsigned share_request_sites(const uint32_t *w, size_t count, size_t *site, uint32_t patched[4]) {
    unsigned found = 0;
    for (size_t i = 0; i + 3 < count; i++) {
        uint32_t and = w[i], tst = w[i + 1], cinc = w[i + 3];
        int x;
        if ((and & 0xffe0fc00u) != 0x0a000000u) continue;
        int d = and & 31, n = (and >> 5) & 31;
        if ((tst & 0xffe0fc1fu) != 0x6a00001fu || (int)((tst >> 5) & 31) != d) continue;
        if (!share_reset_load(w[i + 2], &x) || x == d) continue;
        if ((cinc & 0xffe0fc00u) != 0x1a800400u || (int)((cinc >> 16) & 31) != x ||
            (int)((cinc >> 5) & 31) != x) continue;
        uint32_t c = (tst >> 16) & 31, y = cinc & 31;
        *site = i;
        patched[0] = 0x6a000000u | (c << 16) | ((uint32_t)n << 5) | (uint32_t)d;
        patched[1] = w[i + 2];
        patched[2] = 0x0b000400u | ((uint32_t)d << 16) | ((uint32_t)x << 5) | y;
        patched[3] = 0xd503201fu;
        found++;
    }
    return found;
}

/* MGCopyAnswer is `mov x1, #0` then `b answer`. Returns the byte offset of
 * `answer` from the `b`, or 0 when the function has another shape. */
static int64_t share_answer_branch(const uint32_t *w) {
    if (w[0] != 0xd2800001u || (w[1] & 0xfc000000u) != 0x14000000u) return 0;
    int64_t imm = w[1] & 0x03ffffffu;
    if (imm & 0x02000000) imm -= 0x04000000;
    return imm * 4;
}

/* misd's operating-mode table; 203 is Apple's local network with DHCP. */
static unsigned share_mode_tables(const void *bytes, size_t size) {
    const uint32_t table[] = {201, 201, 202, 203};
    unsigned count = 0;
    for (size_t i = 0; i + sizeof table <= size; i += 4)
        if (!memcmp((const char *)bytes + i, table, sizeof table)) count++;
    return count;
}

static int share_contains(const void *bytes, size_t size, const char *needle) {
    size_t n = strlen(needle) + 1;
    if (n > size) return 0;
    for (size_t i = 0; i + n <= size; i++)
        if (!memcmp((const char *)bytes + i, needle, n)) return 1;
    return 0;
}

static uint64_t share_local_mode(const char *key, uint64_t value, int no_cellular, int supported) {
    return supported && no_cellular && key && !strcmp(key, "opMode") &&
        (value == 200 || value == 201) ? 203 : value;
}

/* getTetheringStatus: must return int and take the known status struct.
 * Frame offsets differ between toolchains, so only the shape is compared. */
static int share_tethering_signature(const char *sig) {
    static const char shape[] =
        "^{mis_ctinterface_tethering_status=BBBI{mis_ctinterface_ct_conn_status=ii[16c]}}";
    return sig && sig[0] == 'i' && strstr(sig, shape) != NULL;
}

/* isDataPlanEnabled: must return int and take a BOOL pointer. */
static int share_data_plan_signature(const char *sig) {
    return sig && sig[0] == 'i' && strstr(sig, "^B") != NULL;
}

/* Wi-Fi driver channel entry (SIOCGA80211, supported channels). */
struct share_channel { uint32_t version, channel, flags; };
#define SHARE_CHANNEL_5GHZ 0x10u
#define SHARE_CHANNEL_DFS 0x100u

/* wifid's stock hotspot channel list on older iOS. */
static const uint32_t share_stock_channels[3] = {1, 6, 11};

static unsigned share_channel_lists(const void *bytes, size_t size, size_t *offset) {
    unsigned count = 0;
    for (size_t i = 0; i + sizeof share_stock_channels <= size; i += 4)
        if (!memcmp((const char *)bytes + i, share_stock_channels, sizeof share_stock_channels)) {
            *offset = i;
            count++;
        }
    return count;
}

/* Up to three non-DFS 5 GHz channels the driver offers right now, in the
 * order {36, 40, 44, 48}. The driver's list already reflects the region.
 * Fewer than three repeat the last one; none returns 0. */
static unsigned share_pick_5ghz(const struct share_channel *list, unsigned count, uint32_t out[3]) {
    static const uint32_t preferred[] = {36, 40, 44, 48};
    unsigned picked = 0;
    for (unsigned p = 0; p < 4 && picked < 3; p++)
        for (unsigned i = 0; i < count; i++)
            if (list[i].channel == preferred[p] && (list[i].flags & SHARE_CHANNEL_5GHZ) &&
                !(list[i].flags & SHARE_CHANNEL_DFS)) {
                out[picked++] = preferred[p];
                break;
            }
    for (unsigned i = picked; picked && i < 3; i++) out[i] = out[picked - 1];
    return picked;
}
#endif
