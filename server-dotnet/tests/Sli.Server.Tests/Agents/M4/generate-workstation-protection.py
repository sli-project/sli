import json,sys,pathlib,html,copy,hashlib
from datetime import datetime,timezone
sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_collect.packets import make_packet
from sli_collect.eventlog import parse_event_xml
from server.sli.plugins.workstations.importer import project_packet
from server.sli.plugins.workstations.contracts import Workstation
host='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; generation='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';channel='Microsoft-Windows-Windows Defender/Operational';provider='Microsoft-Windows-Windows Defender'
class Cur:
 def __init__(self):self.items=[]
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def execute(self,sql,params):self.items.append((sql,params))
 def fetchone(self):return {'id':'ok'}
class Conn:
 def __init__(self):self.c=Cur()
 def cursor(self):return self.c
class Identity:
 def workstation(self,conn,key):return Workstation(key,23,None)
def fixture(name,with_event,state):
 rows=[]
 if with_event:
  xml=("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='"+provider+"'/><EventID>5001</EventID><EventRecordID>1</EventRecordID><Channel>"+channel+"</Channel><TimeCreated SystemTime='2026-10-07T12:34:56Z'/><Computer>synthetic.example</Computer></System><EventData/></Event>")
  rows=[parse_event_xml(xml,source_name=host,connect_address='',channel=channel)]
 packet=make_packet(source=host,channel=channel,generation=generation,cursor={'after_record_id':None,'last_record_id':len(rows) or None},records=[{'format':'event_xml','record_id':r['record_id'],'payload':r} for r in rows],continuity={'status':'not_proven'},observed_at=datetime(2026,10,7,12,35,tzinfo=timezone.utc),context={'workstations':{'protection_state':state}})
 conn=Conn();result=project_packet(conn,packet,rows,agent_key=host,identity=Identity())
 return {'name':name,'packet':packet,'rows':rows,'agent_key':host,'result':result,'observations':[{'id':p[0],'document':json.loads(p[7]),'hash':p[8]} for sql,p in conn.c.items if 'observations' in sql], 'state_id':next(p[0] for sql,p in conn.c.items if 'protection_state' in sql),'state_hash':next(p[6] for sql,p in conn.c.items if 'protection_state' in sql)}
keys=['antivirus_enabled','real_time_protection_enabled','behavior_monitor_enabled','ioav_protection_enabled','nis_enabled','tamper_protected']
a={'state':'available','components':dict(zip(keys,[True,False,None,True,None,False]))};u={'state':'unavailable','components':dict.fromkeys(keys)}
out=[fixture('state-only',False,a),fixture('mixed',True,u)];bad=[]
for name,mutate in [('wrong-channel',lambda p:p['header'].update(channel='Security')),('numeric-bool',lambda p:p['context']['workstations']['protection_state']['components'].update(antivirus_enabled=1)),('extra',lambda p:p['context']['workstations']['protection_state']['components'].update(extra=None)),('unavailable-true',lambda p:p['context']['workstations']['protection_state'].update(state='unavailable'))]:
 packet=copy.deepcopy(out[0]['packet']);mutate(packet)
 try:project_packet(Conn(),packet,[],agent_key=host,identity=Identity());accepted=True
 except ValueError:accepted=False
 bad.append({'name':name,'packet':packet,'accepted':accepted})
pathlib.Path(sys.argv[1]).write_text(json.dumps({'positive':out,'negative':bad},ensure_ascii=True,indent=2),encoding='utf-8')
print('source state packets:',len(out),'negative rejects:',sum(not x['accepted'] for x in bad))
