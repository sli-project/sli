import json,sys,pathlib,html
from datetime import datetime,timezone
sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_collect.packets import make_packet
from sli_collect.eventlog import parse_event_xml
from server.sli.plugins.workstations.importer import project_packet
from server.sli.plugins.workstations.contracts import Workstation
host='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; generation='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
class Cur:
 def __init__(self):self.items=[]
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def execute(self,sql,params):self.items.append(params)
 def fetchone(self):return {'id':'ok'}
class Conn:
 def __init__(self):self.c=Cur()
 def cursor(self):return self.c
class Identity:
 def workstation(self,conn,key):return Workstation(key,23,None)
def row(event,number,channel,provider,data):
 values=''.join('<Data Name="'+html.escape(k)+'">'+html.escape(v)+'</Data>' for k,v in data.items())
 xml=("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='"+provider+"'/><EventID>"+str(event)+"</EventID><EventRecordID>"+str(number)+"</EventRecordID><Channel>"+channel+"</Channel><TimeCreated SystemTime='2026-10-07T12:34:56Z'/><Computer>synthetic.example</Computer></System><EventData>"+values+"</EventData></Event>")
 return parse_event_xml(xml,source_name=host,connect_address='',channel=channel)
def fixture(name,channel,provider,inputs):
 rows=[row(event,index+1,channel,provider,data) for index,(event,data) in enumerate(inputs)]
 packet=make_packet(source=host,channel=channel,generation=generation,cursor={'after_record_id':None,'last_record_id':len(rows)},records=[{'format':'event_xml','record_id':r['record_id'],'payload':r} for r in rows],continuity={'status':'not_proven'},observed_at=datetime(2026,10,7,12,35,tzinfo=timezone.utc))
 conn=Conn(); result=project_packet(conn,packet,rows,agent_key=host,identity=Identity())
 return {'name':name,'packet':packet,'rows':rows,'agent_key':host,'entity_id':23,'ad_computer_id':None,'expected_result':result,'observations':[{'id':x[0],'document':json.loads(x[7]),'hash':x[8]} for x in conn.c.items]}
out=[fixture('security','Security','Microsoft-Windows-Security-Auditing',[(6416,{'DeviceId':'keyboard'}),(6416,{'DeviceId':'USBSTOR\\disk','ClassName':'DiskDrive'})]),fixture('pnp','Microsoft-Windows-Kernel-PnP/Configuration','Microsoft-Windows-Kernel-PnP',[(400,{'DeviceInstanceId':'U\u017fB\ufb05OR\\disk','DeviceName':'synthetic'}),(410,{'DeviceId':'UßBSTOR\\bad'}),(400,{'DeviceId':'UſBﬆOR\\second'}),(420,{'ClassName':'DiSkDrIvE','IsRemovable':'true','Location':'front'})]),fixture('driver','Microsoft-Windows-DriverFrameworks-UserMode/Operational','Microsoft-Windows-DriverFrameworks-UserMode',[(2003,{'DeviceId':'UASPSTOR\\disk'}),(2100,{'ClassName':'keyboard','IsRemovable':'1'}),(2101,{'ClassGuid':'volume','Removable':'1'})]),fixture('all-ignored','Microsoft-Windows-Kernel-PnP/Configuration','Microsoft-Windows-Kernel-PnP',[(410,{'DeviceId':'PCI\\device'})])]
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,ensure_ascii=True,indent=2),encoding='utf-8')
print('source USB packets:',len(out),'observed:',sum(x['expected_result']['observed'] for x in out),'ignored:',sum(x['expected_result']['ignored'] for x in out))

