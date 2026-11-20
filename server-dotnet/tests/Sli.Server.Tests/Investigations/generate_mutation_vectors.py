import ast,json,pathlib
source=pathlib.Path('server/sli/semantic/investigation_cases.py')
tree=ast.parse(source.read_text(encoding='utf-8'))
names={'update_case_status','assign_owner','InvestigationCaseError'}
nodes=[n for n in tree.body if (isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names) or (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in {'VALID_STATUSES','STATUS_TRANSITIONS'} for t in n.targets))]
ns={'__name__':'source_vectors'}
exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),*nodes],type_ignores=[])),str(source),'exec'),ns)
states=['new','active','review','confirmed','closed']
class Cursor:
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def execute(self,sql,args):
  if sql.lstrip().startswith('update investigations'): self.parent['status']=args[0]
  self.commands.append('audit' if 'investigation_audit' in sql else 'update')
class Conn:
 def __init__(self,row): self.row=row;self.cur=Cursor();self.cur.parent=row;self.cur.commands=[]
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def cursor(self):return self.cur
vectors=[]
for old in states:
 for target in states:
  row={'id':1,'status':old}; conn=Conn(row);ns['connect']=lambda:conn;ns['_case_row']=lambda *args:dict(row)
  try:
   result=ns['update_case_status'](investigation_id=1,status=target,actor='a')
   entry={'old':old,'target':target,'status':'ok','replay':bool(result.get('idempotent_replay')),'commands':conn.cur.commands}
  except ns['InvestigationCaseError'] as exc: entry={'old':old,'target':target,'status':exc.code,'message':str(exc),'commands':conn.cur.commands}
  vectors.append(entry)
path=pathlib.Path('server-dotnet/tests/Sli.Server.Tests/Investigations/Fixtures/mutation-source-vectors.json')
path.write_text(json.dumps(vectors,indent=2)+'\n',encoding='utf-8')
print('actual frozen status outcomes:',len(vectors))
