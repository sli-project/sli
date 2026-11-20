import json,sys,dataclasses
from datetime import datetime,timezone
import pathlib; sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_agent.ad_dc import DCHistoryModule
from server.sli.plugins.ad.agent_policy import dc_event_rows
vectors=json.load(open('agent-dotnet/tests/vectors/ad-dc-scenarios.json',encoding='utf-8'))
s=vectors[0]; example=json.loads(s['steps'][0]['expected']['payload_canonical']); xml=example['records'][0]['payload']['xml']
host=s['host_id']; config={'source_name':'fixture-dc','connect_address':'fixture-endpoint','channels':{'System':False,'Directory Service':False},'history_before_utc':'2026-10-08T00:00:00Z'}
now=datetime(2026,10,7,12,tzinfo=timezone.utc); out=[]
for rows in [[(xml,'bookmark')],[]]:
    module=DCHistoryModule(host,config,reader=lambda channel,cursor,limit,rows=rows: rows)
    sample=module.collect(now=now); value=dataclasses.asdict(sample); env={**value,'filtered_count':sample.filtered_count,'lost_count':sample.lost_count}; binding={'source_name':config['source_name']}
    assert dc_event_rows(env,sample.payload,binding,module.config)==[r['payload'] for r in sample.payload['records']]
    out.append({'config':config,'policy':module.config,'sample':value})
open(sys.argv[1],'w',encoding='utf-8').write(json.dumps(out,ensure_ascii=True))
print('source history vectors',len(out))

