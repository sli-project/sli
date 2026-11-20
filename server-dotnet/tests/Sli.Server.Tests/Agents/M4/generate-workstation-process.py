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
out=[fixture('security','Security','Microsoft-Windows-Security-Auditing',[
 (4688,{'SubjectUserSid':'S-1-5-18','SubjectUserName':'SYSTEM','SubjectDomainName':'NT AUTHORITY','SubjectLogonId':'0xAA','NewProcessId':'0x_1f','CreatorProcessId':'٠١٢','NewProcessName':'C:\\synthetic.exe','CommandLine':' synthetic --value=demo ','TargetUserName':'Alice','TargetDomainName':'D','IpAddress':'192.0.2.1'}),
 (4697,{'SubjectUserName':'D\\ Installer','SubjectLogonId':'0x25','ServiceName':'DemoSvc','ImagePath':'C:\\demo.exe --test','AccountName':'SYSTEM','ServiceStartType':'2','ClientProcessId':'4294967295'}),
 (4688,{'NewProcessId':'0','CreatorProcessId':'4294967296','NewProcessName':'界'*171,'CommandLine':'é'*2049}),
 (4688,{'NewProcessId':'-','CreatorProcessId':'0xZ','NewProcessName':'-','CommandLine':'-'}),
 (4624,{'TargetUserName':'D\\User','TargetLogonId':'0x10'})]),
 fixture('system','System','Service Control Manager',[
 (7045,{'ServiceName':'DemoSvc','ServiceFileName':'C:\\demo.exe --value=test','ServiceAccount':'SYSTEM','ServiceStartType':'auto','SubjectUserName':'Bob','SubjectDomainName':'D'}),
 (7036,{'ServiceName':'DemoSvc','State':'running'})])]
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,ensure_ascii=True,indent=2),encoding='utf-8')
print('source process packets:',len(out),'observations:',sum(x['expected_result']['observed'] for x in out))