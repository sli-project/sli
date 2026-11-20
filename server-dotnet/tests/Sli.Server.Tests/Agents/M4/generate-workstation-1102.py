import json,sys,pathlib
from datetime import datetime,timezone
sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_collect.packets import make_packet
from sli_collect.eventlog import parse_event_xml
from server.sli.plugins.workstations.importer import project_packet
from server.sli.plugins.workstations.contracts import Workstation
host='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; generation='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><EventRecordID>7</EventRecordID><Channel>Security</Channel><TimeCreated SystemTime='2026-10-07T12:34:56.1234567Z'/><Computer>synthetic.example</Computer></System><EventData><Data Name='CollectionFieldsTruncated'>true</Data></EventData></Event>"
row=parse_event_xml(xml,source_name=host,connect_address='',channel='Security')
packet=make_packet(source=host,channel='Security',generation=generation,cursor={'after_record_id':None,'last_record_id':7},records=[{'format':'event_xml','record_id':7,'payload':row}],continuity={'status':'not_proven'},observed_at=datetime(2026,10,7,12,35,tzinfo=timezone.utc))
class Cur:
 def __init__(self): self.items=[]
 def __enter__(self): return self
 def __exit__(self,*args): pass
 def execute(self,sql,params): self.items.append(params)
 def fetchone(self): return {'id':'ok'}
class Conn:
 def __init__(self): self.c=Cur()
 def cursor(self): return self.c
class Identity:
 def workstation(self,conn,key): return Workstation(key,23,None)
conn=Conn(); result=project_packet(conn,packet,[row],agent_key=host,identity=Identity()); a=conn.c.items[0]
assert result=={'observed':1,'inserted':1,'ignored':0}
out={'packet':packet,'rows':[row],'agent_key':host,'entity_id':23,'ad_computer_id':None,'observation_id':a[0],'observation':json.loads(a[7]),'observation_sha256':a[8]}
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,ensure_ascii=True,indent=2),encoding='utf-8')
print('source workstation 1102 projection and digest captured')
