import json,sys
from sli_agent.workstations import _policy
cases=[{}, {"policy_revision":"9","families":{"processes":False},"rate_limits":{"4104":200},"allow_process_paths":["C:\\Tools\\Straße"]}, {"family_filters":{"processes":{"deny_event_ids":[4688]},"logons":{"allow_event_ids":[4624]}}}, {"deny_event_ids":None}, {"allow_process_paths":None}, {"families":{"missing":True}}, {"rate_limits":{"04104":1}}, {"allow_process_paths":["😀"*512]}, {"protected_services":["\u001c"]}, {"channel_generations":{"Security":"\u001c"}}]
out=[]
for value in cases:
 try: out.append({"input":value,"result":_policy(value),"ok":True})
 except ValueError: out.append({"input":value,"ok":False})
open(sys.argv[1],"w",encoding="utf8").write(json.dumps(out,ensure_ascii=True,sort_keys=True)+"\n")
