# Trims real MSRC CVRF v3 documents to a few CVEs and products for test fixtures.
import json,re,sys,os
src,out=sys.argv[1],sys.argv[2]
keep_cves={
 '2024-Oct':['CVE-2024-43583'],
 '2025-Sep':['CVE-2025-59220','CVE-2025-53803'],
 '2025-Oct':['CVE-2025-59287','CVE-2025-59230','CVE-2025-59289','CVE-2025-55247','CVE-2016-9535'],
 '2026-Oct':['CVE-2026-69950'],
}
want_names=re.compile(r'^(Windows Server (2016|2019|2022|2025)( \(Server Core installation\))?|Windows Server 2022, 23H2 Edition \(Server Core installation\)|Windows Server 2012 R2|'
  r'Windows 10 Version (1607|21H2) for x64-based Systems|Windows 10 Version 22H2 for (x64-based|ARM64-based|32-bit) Systems|'
  r'Windows 11 Version (22H2|23H2|25H2) for x64-based Systems|Windows 11 Version 24H2 for (x64|ARM64)-based Systems|'
  r'Microsoft \.NET Framework 3\.5 AND 4\.8\.1 on Windows Server 2022|Windows Server 2008 R2 for x64-based Systems Service Pack 1)$')
os.makedirs(out,exist_ok=True)
idx=json.load(open(os.path.join(src,'updates.json')))
idx['value']=[v for v in idx['value'] if v['ID'] in keep_cves or v['ID']=='1999-Sep']
json.dump(idx,open(os.path.join(out,'updates.json'),'w'),separators=(',',':'))
for doc,cves in keep_cves.items():
  d=json.load(open(os.path.join(src,doc+'.json')))
  prods=[p for p in d['ProductTree']['FullProductName'] if want_names.match(p['Value'])]
  ids={p['ProductID'] for p in prods}
  d['ProductTree']={'FullProductName':prods}
  d['DocumentNotes']=d['DocumentNotes'][:1]
  vs=[]
  for v in d['Vulnerability']:
    if v['CVE'] not in cves: continue
    v.pop('Acknowledgments',None)
    v['Notes']=[n for n in v.get('Notes',[]) if n.get('Title')=='Description'][:1]
    for k in ('ProductStatuses','Threats','CVSSScoreSets','Remediations'):
      lst=[]
      for e in v.get(k,[]):
        pid=[p for p in e.get('ProductID',[]) if p in ids]
        if pid: e['ProductID']=pid; lst.append(e)
      v[k]=lst
    vs.append(v)
  assert len(vs)==len(cves),(doc,[v['CVE'] for v in vs])
  d['Vulnerability']=vs
  json.dump(d,open(os.path.join(out,doc+'.json'),'w'),separators=(',',':'))
