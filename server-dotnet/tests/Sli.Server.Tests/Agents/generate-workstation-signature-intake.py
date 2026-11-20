import json,sys,pathlib,copy,hashlib
sys.path.insert(0,str(pathlib.Path.cwd()))
from server.sli.agents.workstation_ingest import workstation_rows
fixtures=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
f=next(x for x in fixtures if x['name']=='process-filters');s=f['steps'][0];p=json.loads(s['payload_canonical']);r=p['records'][0]['payload'];host=f['host_id'];now=p['header']['observed_at_utc']
m={'scope':'file_at_measurement','observed_at_utc':now,'status':'signed','reason':None,'sha256_before':'a'*64,'sha256_after':'a'*64,'identity_before':'b'*64,'identity_after':'b'*64,'signer_sha256':'c'*64,'kind':'embedded'}
sig={'contract':'sli.workstation-file-signature.v1','record_id':r['record_id'],'path':r['properties'][0],'source_sha256':hashlib.sha256(r['xml'].encode()).hexdigest(),'measurement':m}
p['context']['workstations']['process_signatures']=[sig]
e={'source_instance_id':host,'generation':host,'channel':'workstations','module_version':'1.1.0','payload_contract':'sli.collection-packet.v1','policy_revision':f['config'].get('policy_revision','1'),'cursor_before':s['cursor_before'],'cursor_after':s['cursor_after'],'filtered_count':s['filtered_count'],'lost_count':s['lost_count'],'continuity_state':s['continuity_state']}
i={'host_id':host,'assigned_modules':[{'module_id':'sli.workstations','enabled':True,'config':f['config']}]}
out=[]
for name in ('valid','invalid_hash','float_event'):
 packet=copy.deepcopy(p)
 if name=='invalid_hash':packet['context']['workstations']['process_signatures'][0]['source_sha256']='0'*64
 if name=='float_event':packet['records'][0]['payload']['event_id']=4688.0
 try:workstation_rows(i,e,packet);accepted=True
 except ValueError as err:accepted=False
 out.append({'name':name,'payload':packet,'envelope':e,'host_id':host,'config':f['config'],'source_accepted':accepted})
 print(name,'source_accepted',accepted)
pathlib.Path(sys.argv[2]).write_text(json.dumps(out,ensure_ascii=True,indent=2),encoding='utf-8')
