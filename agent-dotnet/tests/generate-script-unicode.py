import json,pathlib,sys
sys.path.insert(0,str(pathlib.Path.cwd()))
from sli_agent.script_secrets import mask_script_secrets
vectors=[
 ('long_s','Paſſword=synthetic123'),('dotless_i','-Credentıal synthetic123'),('dotted_i','-Credentİal synthetic123'),
 ('kelvin','AccountKey=synthetic123'),('combining_before','\u0301Password=synthetic123'),('numeric_before','²Password=synthetic123'),
 ('connector_before','\u203fPassword=synthetic123'),('astral_letter_before','𐐀Password=synthetic123'),('astral_emoji_before','😀Password=synthetic123'),
 ('combining_after','Password\u0301=synthetic123'),('space_control','Password=synthetic123\u001cNext'),('plain','Password=synthetic123'),
 ('auth_alias','Basıc QUJDREVGR0g5QUJDREVGRw=='),('cloud','client_ſecret=synthetic123'),('pipeline',"'synthetic123' | ConvertTo-SecureString -AsPlainText"),
 ('option-long-s',"ConvertTo-SecureString -ſtring 'synthetic123' -AsPlainText"),
 ('option-dotless-i',"ConvertTo-SecureString -Strıng 'synthetic123' -AsPlainText"),
 ('option-dotted-i',"ConvertTo-SecureString -Strİng 'synthetic123' -AsPlainText"),
 ('option-ascii',"ConvertTo-SecureString -String 'synthetic123' -AsPlainText"),
 ('benign','Write-Output safe'),('quoted',"Password='synthetic value'"),('bounds','é'*4100)]
out=[]
for name,script in vectors:
 text,count,truncated=mask_script_secrets(script)
 out.append(dict(name=name,script=script,text=text,count=count,truncated=truncated))
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,ensure_ascii=True,indent=2),encoding='utf-8')
print('source synthetic masking vectors:',len(out))
