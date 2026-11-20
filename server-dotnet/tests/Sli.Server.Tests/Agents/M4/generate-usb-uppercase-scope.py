import json,pathlib,sys,unicodedata
allowed=set('USBTORAP')
rows=[{'codepoint':f'{n:04X}','upper':chr(n).upper()} for n in range(128,0x110000) if not 0xd800<=n<=0xdfff and chr(n).upper()!=chr(n) and set(chr(n).upper())<=allowed]
assert rows==[{'codepoint':'00DF','upper':'SS'},{'codepoint':'017F','upper':'S'},{'codepoint':'FB05','upper':'ST'},{'codepoint':'FB06','upper':'ST'}]
pathlib.Path(sys.argv[1]).write_text(json.dumps({'unicode':unicodedata.unidata_version,'target_ascii':'USBTORAP','mappings':rows},indent=2),encoding='utf-8')
print('Python 3.14 prefix-target uppercase mappings:',len(rows),'Unicode',unicodedata.unidata_version)
