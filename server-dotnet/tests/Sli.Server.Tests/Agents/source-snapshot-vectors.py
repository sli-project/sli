import sys,pathlib,json,copy,base64
sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_agent.snapshot_stream import policy,cursor,validate_chunk
out=[]
def case(label,module,mutate=lambda e,p:None):
  cfg=policy(module,{'source_instance_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','domain_sid':'S-1-5-21-1-2-3','domain_dns':'example.test','scope':'domain'})
  p={'contract':module+'.chunk.v1','cycle_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','family':cfg['families'][0], 'slot_start_utc':'2026-10-07T11:00:00+00:00','chunk_index':0,'chunk_count':1,'total_objects':0,'total_bytes':0,'family_sha256':'a'*64,'records':[{'data_b64':''}],'cycle_families':cfg['families'],'domain_sid':cfg['domain_sid'],'domain_dns':cfg['domain_dns'],'scope':cfg['scope']}
  e={'contract_id':'sli.agent-envelope.v1','packet_id':'cccccccc-cccc-4ccc-8ccc-cccccccccccc','agent_id':'dddddddd-dddd-4ddd-8ddd-dddddddddddd','source_instance_id':cfg['source_instance_id'],'module_id':module,'module_version':'1.0.0','policy_revision':'1','channel':'snapshot','generation':cfg['source_instance_id'],'sequence':1,'cursor_before':{'strategy':'snapshot','token':''},'cursor_after':cursor(p),'payload_contract':module+'.chunk.v1','payload_sha256':'a'*64,'record_count':1,'payload_bytes':0,'observed_at_utc':'2026-10-07T11:00:01+00:00','continuity_state':'complete','filtered_count':0,'lost_count':0}
  mutate(e,p)
  try: validate_chunk(e,p,cfg); valid=True
  except (ValueError,TypeError,KeyError): valid=False
  out.append({'name':label,'envelope':e,'payload':p,'config':cfg,'valid':valid})
case('ad_empty','sli.ad-snapshot'); case('gpo_empty','sli.gpo-snapshot')
case('bad_fragment','sli.gpo-snapshot',lambda e,p:p['records'][0].update(data_b64='AA=='))
case('bool_objects','sli.gpo-snapshot',lambda e,p:p.update(total_objects=True))
case('bad_scope','sli.gpo-snapshot',lambda e,p:p.update(scope='other'))
case('wrong_after','sli.gpo-snapshot',lambda e,p:e['cursor_after'].update(token=''))
case('subsecond_slot','sli.gpo-snapshot',lambda e,p:p.update(slot_start_utc='2026-10-07T11:00:00.000001+00:00'))
case('uppercase_digest','sli.gpo-snapshot',lambda e,p:p.update(family_sha256='A'*64))
def first_fragment(e,p):
  p.update(total_bytes=32769,chunk_count=2); p['records'][0]['data_b64']=base64.b64encode(bytes(32768)).decode(); e['cursor_after']=cursor(p)
case('gpo_first_fragment','sli.gpo-snapshot',first_fragment)
def second_fragment(e,p):
  first_fragment(e,p); e['cursor_before']=e['cursor_after']; p['chunk_index']=1; p['records'][0]['data_b64']='AA=='; e['cursor_after']=cursor(p)
case('gpo_second_fragment','sli.gpo-snapshot',second_fragment)
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,ensure_ascii=True),encoding='ascii')
print('source snapshot chunk vectors',len(out))
