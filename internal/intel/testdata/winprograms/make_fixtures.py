# Cuts the Windows program test fixtures out of real upstream data, unchanged
# except for being trimmed to a few records:
#
#   nvd/<cpe>.json     NVD CVE API 2.0 answers (one page) for a CPE product,
#                      holding real CVE records saved from
#                      services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=<cpe>
#   msrc-updates.json  a Security Update Guide index listing 2026-Oct only
#   msrc-2026-Oct.json the real 2026-Oct CVRF document trimmed to the CVEs
#                      and products below (Edge, .NET, ASP.NET Core, Server 2022)
#   mfsa.tar.gz        Mozilla's foundation-security-advisories archive
#                      trimmed to the advisories below
#
# usage: python3 -I make_fixtures.py <nvd dir> <cvrf-2026-Oct.json> <msrc updates.json> <mfsa archive dir> <out dir>
import io, json, os, re, sys, tarfile

nvd_dir, cvrf, updates, mfsa_dir, out = sys.argv[1:6]

NVD = {
    # Chrome: newest, in KEV (CVE-2025-6554, CVE-2025-2783), Android only.
    "cpe:2.3:a:google:chrome": ["CVE-2026-118359", "CVE-2025-6554", "CVE-2025-2783", "CVE-2025-0435"],
    # 7-Zip: in KEV (CVE-2025-0411), newest.
    "cpe:2.3:a:7-zip:7-zip": ["CVE-2025-0411", "CVE-2026-14266", "CVE-2026-48103"],
    # Zoom: Windows client, Linux client only.
    "cpe:2.3:a:zoom:workplace_desktop": ["CVE-2025-46785", "CVE-2025-46788"],
    # Adobe: Continuous and Classic ranges in one CVE, an older Classic one.
    "cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous": ["CVE-2026-81997", "CVE-2024-20726"],
    "cpe:2.3:a:adobe:acrobat:*:*:*:*:classic": ["CVE-2026-81997", "CVE-2024-20726"],
}
NVD_FILES = {
    "cpe:2.3:a:google:chrome": "cpe_2.3_a_google_chrome.json",
    "cpe:2.3:a:7-zip:7-zip": "cpe_2.3_a_7-zip_7-zip.json",
    "cpe:2.3:a:zoom:workplace_desktop": "cpe_2.3_a_zoom_workplace_desktop.json",
    "cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous": "cpe_2.3_a_adobe_acrobat_dc.json",
    "cpe:2.3:a:adobe:acrobat:*:*:*:*:classic": "cpe_2.3_a_adobe_acrobat.json",
}
os.makedirs(os.path.join(out, "nvd"), exist_ok=True)
for cpe, cves in NVD.items():
    recs = {x["cve"]["id"]: x for x in json.load(open(os.path.join(nvd_dir, NVD_FILES[cpe])))}
    vulns = [recs[c] for c in cves]
    page = {"resultsPerPage": len(vulns), "startIndex": 0, "totalResults": len(vulns), "format": "NVD_CVE",
            "version": "2.0", "timestamp": "2026-10-30T08:00:00.000", "vulnerabilities": vulns}
    name = re.sub(r"[^a-z0-9.]+", "_", cpe.replace("cpe:2.3:a:", "").replace(":*", "")).strip("_") + ".json"
    json.dump(page, open(os.path.join(out, "nvd", name), "w"), separators=(",", ":"))

# Security Update Guide: Edge (one fix; Stable and Extended Stable fixes),
# .NET runtime fixes per line, SDK versions only, ASP.NET Core, Windows.
# Edge: 156 only on 10-22 and 10-27, 152 next to 155 on 10-16 and 10-26.
CVRF_CVES = ["CVE-2026-102299", "CVE-2026-110144", "CVE-2026-110913", "CVE-2026-112992", "CVE-2026-20942",
             "CVE-2026-105016", "CVE-2026-114148", "CVE-2026-69950"]
want = re.compile(r"^(Microsoft Edge \(Chromium-based\)|\.NET (8|9|10)\.0( runtime)? installed on Windows|ASP\.NET Core (8|9|10)\.0|"
                  r"Windows Server 2022( \(Server Core installation\))?)$")
d = json.load(open(cvrf))
prods = [p for p in d["ProductTree"]["FullProductName"] if want.match(p["Value"])]
ids = {p["ProductID"] for p in prods}
d["ProductTree"] = {"FullProductName": prods}
d["DocumentNotes"] = d["DocumentNotes"][:1]
vs = []
for v in d["Vulnerability"]:
    if v["CVE"] not in CVRF_CVES:
        continue
    v.pop("Acknowledgments", None)
    v["Notes"] = [n for n in v.get("Notes", []) if n.get("Title") == "Description"][:1]
    for k in ("ProductStatuses", "Threats", "CVSSScoreSets", "Remediations"):
        lst = []
        for e in v.get(k, []):
            pid = [p for p in e.get("ProductID", []) if p in ids]
            if pid:
                e["ProductID"] = pid
                lst.append(e)
        v[k] = lst
    vs.append(v)
assert sorted(v["CVE"] for v in vs) == sorted(CVRF_CVES), [v["CVE"] for v in vs]
d["Vulnerability"] = vs
json.dump(d, open(os.path.join(out, "msrc-2026-Oct.json"), "w"), separators=(",", ":"))
idx = json.load(open(updates))
idx["value"] = [v for v in idx["value"] if v["ID"] == "2026-Oct"]
json.dump(idx, open(os.path.join(out, "msrc-updates.json"), "w"), separators=(",", ":"))

# Mozilla: CVE-2024-9680 (in KEV; Firefox 131.0.2, ESR 128.3.1 and
# 115.16.1, and Thunderbird), the newest Firefox, ESR and Thunderbird
# advisories, one for Firefox for iOS, and a 2016 advisory in prose.
MFSA = ["2024/mfsa2024-51.yml", "2024/mfsa2024-52.yml", "2026/mfsa2026-118.yml", "2026/mfsa2026-119.yml", "2026/mfsa2026-120.yml",
        "2026/mfsa2026-121.yml", "2026/mfsa2026-122.yml", "2016/mfsa2016-01.md"]
root = os.path.basename(mfsa_dir.rstrip("/"))
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    for rel in MFSA:
        data = open(os.path.join(mfsa_dir, "announce", rel), "rb").read()
        ti = tarfile.TarInfo(root + "/announce/" + rel)
        ti.size, ti.mtime = len(data), 0
        tf.addfile(ti, io.BytesIO(data))
open(os.path.join(out, "mfsa.tar.gz"), "wb").write(buf.getvalue())
print("ok")
