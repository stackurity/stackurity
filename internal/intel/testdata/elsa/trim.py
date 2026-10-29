# Trims Oracle's ELSA OVAL files (linux.oracle.com/security/oval/
# com.oracle.elsa-ol<N>.xml.bz2) to a few definitions for test fixtures.
#
#   python3 trim.py <dir with the downloaded .xml.bz2 files> <output dir>
#
# Each kept definition keeps its criteria exactly as published, with the
# tests, objects and states it references; descriptions (changelogs) are cut
# to their first lines. Text is cut out of the original document rather than
# re-serialised, so element order, namespaces and spacing stay Oracle's.
import bz2, os, re, sys

KEEP = {
    'ol7': ['ELSA-2022-9228'],                     # version pattern "^1\.20\." (a line given as a regular expression)
    'ol8': ['ELSA-2021-0218',                      # sudo, CVE-2021-3156 (KEV); the fix listed twice
            'ELSA-2023-12851', 'ELSA-2023-12853',  # glibc, CVE-2023-4911; and its Ksplice build (epoch 2)
            'ELSA-2023-12017',                     # UEK R7 for Oracle Linux 8 and 9 in one definition
            'ELSA-2020-5848',                      # UEK R6 (5.4.17) for Oracle Linux 7 and 8
            'ELSA-2024-6148', 'ELSA-2024-5814',    # nodejs:18 and nodejs:20 module streams
            'ELSA-2024-12135'],                    # FIPS build
    'ol9': ['ELSA-2023-12850', 'ELSA-2023-12854',  # glibc .0.3 rebuild, CVE-2023-4911 (KEV); its Ksplice build
            'ELSA-2023-2650',                      # curl: two alternative fixes for one package
            'ELSA-2023-12017',                     # UEK R7 for Oracle Linux 8 and 9
            'ELSA-2025-20368',                     # UEK R8 (6.12)
            'ELSA-2024-1503', 'ELSA-2024-1688',    # nodejs:18 and nodejs:20 module streams
            'ELSA-2024-12336'],                    # openssl FIPS build (epoch 10)
    'ol10': ['ELSA-2025-20371'],                   # UEK R8 on Oracle Linux 10
}
# Variants of ol9: "shrunk" keeps one definition (a file that lost most of
# its advisories, which the feed must refuse); "revised" drops the curl
# advisory (a revision the feed reads, withdrawing that one advisory).
VARIANTS = {
    'ol9-shrunk': ['ELSA-2023-2650'],
    'ol9-revised': [i for i in KEEP['ol9'] if i != 'ELSA-2023-2650'],
}

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)


def block(tag):
    t = re.escape(tag)
    return re.compile(r'<' + t + r'\b[^>]*\bid="([^"]+)"[^>]*>.*?</' + t + r'>\n?', re.S)


DEF = re.compile(r'<definition [^>]*>.*?</definition>\n?', re.S)
PATTERNS = {
    'tests': [block('rpminfo_test'), block('ind-def:textfilecontent54_test')],
    'objects': [block('rpminfo_object'), block('ind-def:textfilecontent54_object')],
    'states': [block('rpminfo_state'), block('ind-def:textfilecontent54_state')],
}


def section(txt, name):
    s = txt.index('<' + name + '>')
    return s, txt.index('</' + name + '>', s)


def short_description(m):
    return m.group(1) + '\n'.join(m.group(2).split('\n')[:6]) + '\n' + m.group(3)


def build(txt, keep):
    ds, de = section(txt, 'definitions')
    head = txt[:ds]
    defs = {}
    for m in DEF.finditer(txt, ds, de):
        blk = m.group(0)
        m = re.search(r'ref_id="(ELSA-[0-9-]+)"', blk)
        i = m and m.group(1)  # bug fix advisories (ELBA) have none
        if i in keep:
            defs[i] = re.sub(r'(<description>\n)(.*?)(</description>)', short_description, blk, flags=re.S)
    assert set(defs) == set(keep), sorted(set(keep) - set(defs))
    body = ''.join(defs[i] for i in keep)
    want = {'tests': set(re.findall(r'test_ref="([^"]+)"', body))}
    kept = {}
    for name in ('tests', 'objects', 'states'):
        s, e = section(txt, name)
        got = [m.group(0) for p in PATTERNS[name] for m in p.finditer(txt, s, e) if m.group(1) in want[name]]
        assert len(got) == len(want[name]), (name, len(got), len(want[name]))
        kept[name] = got
        if name == 'tests':
            refs = set()
            for g in got:
                refs.update(re.findall(r'(?:object_ref|state_ref)="([^"]+)"', g))
            want['objects'] = {r for r in refs if ':obj:' in r}
            want['states'] = {r for r in refs if ':ste:' in r}
    return (head + '<definitions>\n' + body + '</definitions>\n<tests>\n' + ''.join(kept['tests']) +
            '</tests>\n<objects>\n' + ''.join(kept['objects']) + '</objects>\n<states>\n' + ''.join(kept['states']) +
            '</states>\n</oval_definitions>\n')


def write(name, doc):
    with open(os.path.join(out, 'com.oracle.elsa-' + name + '.xml.bz2'), 'wb') as f:
        f.write(bz2.compress(doc.encode('utf-8'), 9))


for rel, keep in KEEP.items():
    with bz2.open(os.path.join(src, 'com.oracle.elsa-' + rel + '.xml.bz2'), 'rt', encoding='utf-8') as f:
        txt = f.read()
    write(rel, build(txt, keep))
    for name, ids in VARIANTS.items():
        if name.startswith(rel + '-'):
            write(name, build(txt, ids))
