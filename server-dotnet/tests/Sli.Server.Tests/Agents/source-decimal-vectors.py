import json,pathlib,unicodedata,sys
out=[]
for n in range(0x110000):
    ch=chr(n)
    if ch.isdecimal(): out.append([n,unicodedata.decimal(ch)])
pathlib.Path(sys.argv[1]).write_text(json.dumps({'unicode_version':unicodedata.unidata_version,'digits':out}),encoding='ascii')
print('unicode version',unicodedata.unidata_version,'decimal digits',len(out))
