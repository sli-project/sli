import pathlib,sys; sys.path.insert(0,str(pathlib.Path.cwd()))
from server.sli.agents.import_authorization import authorize_packet,PacketPending
from sli_agent.envelope import digest
packet={'synthetic':True}; received={'agent_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','packet_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','module_id':'sli.workstations','sequence':1,'payload_sha256':digest(packet)}
inbox={**received,'sequence':1.0}
class Cursor:
 def __init__(self):self.index=0
 def execute(self,*_):pass
 def fetchone(self):
  self.index+=1
  return {'status':'active','assigned_modules':[{'module_id':'sli.workstations','enabled':True}],'host_id':'cccccccc-cccc-4ccc-8ccc-cccccccccccc'} if self.index==1 else {'envelope':received,'envelope_sha256':digest(received)}
assert received==inbox and digest(received)!=digest(inbox)
try: authorize_packet(Cursor(),inbox,packet,module='sli.workstations')
except PacketPending as e: assert str(e)=='agent_packet_attestation_invalid';print('source rejected numerically equal envelope with different canonical digest before identity')
else: raise AssertionError('source accepted altered inbox')

