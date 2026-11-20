import datetime,json,sys
old=json.load(open(sys.argv[1],encoding='utf-8'))
extra=['2026-01-01','20260101','2026-W01','2026W01','2026-01-01T12','2026-01-01T12:30','2026-01-01T12:30.5','10/28/2026 12:00:00 +00:00','2026-01-01T00:00:00+00:00:00.000001','2026-01-01T00:00:00+00:00:01.000001','2026-01-01T00:00:00-00:00:01.1234567','2026-01-01T00:00:00-00:00:00.1','0001-01-01T00:00:00+01:00','9999-12-31T23:59:59-01:00','2026-01-01T00:00:00+00','2026-01-01T00:00:00-0000','2026-01-01T00:00:00+00:00:00.0000009','2026-01-01T00:00:00+00:00:01.0000009','2026-01-01T12:00:00,123456789Z','2026-01-01💠12:00:00+00:00','2026-01-01T12:00:00+000060','2026-01-01T24:00:00.0000009Z','9999-12-31T24:00Z','2026-01-01Z12:00:00+00:00','２０２６-01-01T00:00:00Z','2026-01-01T٠٠:00:00Z']
def parse(s):
 try:
  t=datetime.datetime.fromisoformat(s); offset=t.utcoffset(); result={'valid':True,'aware':offset is not None,'wall':t.replace(tzinfo=None).isoformat(timespec='microseconds'),'offset_us':None if offset is None else offset//datetime.timedelta(microseconds=1)}
  try: result['utc']=t.astimezone(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec='microseconds') if offset is not None else None
  except (ValueError,OverflowError): result['utc']=None
  return result
 except (ValueError,OverflowError): return {'valid':False}
def utc_source(s):
 try:
  v=datetime.datetime.fromisoformat(s.replace('Z','+00:00')); return v.utcoffset() is not None and v.utcoffset()==datetime.timedelta(0)
 except (ValueError,OverflowError):return False
out=[{'text':s,**parse(s),'utc_source':utc_source(s)} for s in dict.fromkeys([x['value'] for x in old]+extra)]
open(sys.argv[2],'w',encoding='utf-8').write(json.dumps(out,ensure_ascii=True,indent=2))
print('source vectors',len(out),'gpo cases',len(old),'aware',sum(x.get('aware',False) for x in out))
