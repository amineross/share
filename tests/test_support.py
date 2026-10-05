#!/usr/bin/env python3
"""Checks Share's recognition rules.
Set SHARE_FIXTURES to a folder of <release>/misd and <release>/wifid files to
also check real daemons."""
from pathlib import Path
import os, struct, subprocess, tempfile

root = Path(__file__).resolve().parents[1]
fixtures = Path(os.environ['SHARE_FIXTURES']) if 'SHARE_FIXTURES' in os.environ else None

# release: (state gate offset, register) for misd; channel lists in wifid
MISD = {'ios12': (0x1182c, 24), 'ios15': (0x120a8, 25), 'ios16': (0x141b4, 25),
        'ios17': (0x137d8, 25), 'ios17ipad': (0x14308, 25)}
WIFID = {'ios12': 1, 'ios15': 0, 'ios16': 0, 'ios17': 0}

CHECK = r'''#include "share_support.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static const char *sig = "i24@0:8^{mis_ctinterface_tethering_status=BBBI{mis_ctinterface_ct_conn_status=ii[16c]}}16";
static void rules(void) {
    for (int ok = 0; ok < 2; ok++) for (int local = 0; local < 2; local++) for (uint64_t v = 198; v < 207; v++) {
        assert(share_local_mode("opMode", v, local, ok) == ((ok && local && (v == 200 || v == 201)) ? 203 : v));
        assert(share_local_mode("bridgeType", v, local, ok) == v);
        assert(share_local_mode(NULL, v, local, ok) == v);
    }
    uint32_t w[] = {0x321e1fe8, 0x1a808118, 0x321e1fe8, 0x1a808118};
    size_t site; int dest;
    assert(share_patch_sites(w, 4, &site, &dest) == 2);
    assert(share_patch_sites(w, 0, &site, &dest) == 0);
    assert(share_patched_instruction(25) == 0x2a0003f9);
    assert(share_tethering_signature(sig));
    assert(!share_tethering_signature("v24@0:8^{mis_ctinterface_tethering_status=BBBI{mis_ctinterface_ct_conn_status=ii[16c]}}16"));
    assert(!share_tethering_signature("i24@0:8^{mis_ctinterface_tethering_status=BBBQ{mis_ctinterface_ct_conn_status=ii[16c]}}16"));
    assert(!share_tethering_signature(NULL));

    uint32_t out[3];
    struct share_channel all[] = {{1, 6, 0x0a}, {1, 36, 0x12}, {1, 40, 0x12}, {1, 44, 0x12}, {1, 52, 0x112}};
    assert(share_pick_5ghz(all, 5, out) == 3 && out[0] == 36 && out[1] == 40 && out[2] == 44);
    struct share_channel some[] = {{1, 11, 0x0a}, {1, 44, 0x12}, {1, 100, 0x112}};
    assert(share_pick_5ghz(some, 3, out) == 1 && out[0] == 44 && out[2] == 44);
    struct share_channel dfs[] = {{1, 36, 0x112}, {1, 52, 0x112}};
    assert(share_pick_5ghz(dfs, 2, out) == 0);
    assert(share_pick_5ghz(all, 0, out) == 0);
}
int main(int argc, char **argv) {
    if (argc == 1) { rules(); return 0; }
    FILE *f = fopen(argv[2], "rb"); assert(f);
    fseek(f, 0, SEEK_END); size_t n = ftell(f); rewind(f);
    void *b = malloc(n); assert(fread(b, 1, n, f) == n); fclose(f);
    if (argv[1][0] == 'w') { size_t offset; printf("%u\n", share_channel_lists(b, n, &offset)); return 0; }
    size_t site = 0; int dest = 0;
    unsigned count = share_patch_sites(b, n / 4, &site, &dest);
    printf("%u %zu %d %u %d\n", count, site * 4, dest, share_mode_tables(b, n), share_contains(b, n, "opMode"));
    return 0;
}'''

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / 'check.c').write_text(CHECK)
    subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-I', str(root / 'src'),
                    str(tmp / 'check.c'), '-o', str(tmp / 'check')], check=True)
    subprocess.run([str(tmp / 'check')], check=True)
    print('PASS state gate, mode, cellular check and 5 GHz channel rules')
    run = lambda kind, path: subprocess.check_output([str(tmp / 'check'), kind, str(path)]).split()
    for release, (offset, register) in MISD.items():
        path = fixtures / release / 'misd' if fixtures else None
        if not path or not path.exists():
            print('SKIP', release, 'misd'); continue
        values = list(map(int, run('m', path)))
        assert values == [1, offset, register, 1, 1], (release, values)
        doubled = tmp / 'doubled'
        doubled.write_bytes(path.read_bytes() + struct.pack('<4I', 201, 201, 202, 203))
        assert run('m', doubled)[3] == b'2'
        print('PASS', release, 'misd recognized; a duplicate mode table is rejected')
    for release, lists in WIFID.items():
        path = fixtures / release / 'wifid' if fixtures else None
        if not path or not path.exists():
            print('SKIP', release, 'wifid'); continue
        assert int(run('w', path)[0]) == lists, release
        print('PASS', release, 'wifid', 'has the 2.4 GHz list' if lists else 'picks its band itself')
