import json,sys,dataclasses,pathlib
from datetime import datetime,timezone
sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_agent.ad_dc import ADDCModule
from server.sli.plugins.ad.agent_policy import dc_event_rows
host='6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f'; now=datetime(2026,10,7,12,tzinfo=timezone.utc)
config={'source_name':'fixture-dc','connect_address':'fixture-endpoint','initial_read_hours':'all','channels':{'System':False,'Directory Service':False}}
cursor={'next':1,'channels':{'Security':{'record_id':9223372036854775808,'bookmark':'anchor','generation':host,'since_utc':'2026-W01-1T00:00:00+00:00:00'}}}
captured={'generation':host,'cursor_after':{'strategy':'bookmark','token':json.dumps(cursor,separators=(',',':'))}}
module=ADDCModule(host,config,reader=lambda *_:[]); sample=module.collect(captured,now=now); value=dataclasses.asdict(sample)
assert dc_event_rows(value,sample.payload,{'source_name':'fixture-dc'},module.config)==[]
open(sys.argv[1],'w',encoding='utf-8').write(json.dumps({'config':config,'policy':module.config,'sample':value},ensure_ascii=True))
print('source accepted: big integer cursor and compact ISO week + seconds zero offset')
