"""Offline frozen Python function calls only. No application imports or database IO.
Run with the existing Python and PYTHONDONTWRITEBYTECODE=1. Writes one fixture.
"""
import ast
import json
import runpy
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

ROOT = Path(__file__).resolve().parents[4]
body_only = '--body-only' in sys.argv
SCOPE = ROOT / 'server/sli/access/scope.py'
scope_globals = runpy.run_path(str(SCOPE))  # stdlib-only immutable scope implementation
access_path = ROOT / 'server/sli/access/access_composition.py'
names = {'normalize_capability_scope', '_scope_matches_resource', 'capability_decision_for_resource_groups', '_report_scope_is_global', 'report_action_decision'}
parsed = ast.parse(access_path.read_text(encoding='utf-8'))
namespace = {'Any': Any, 'Mapping': Mapping, 'Sequence': Sequence, 'json': json, 'AccessScope': scope_globals['AccessScope']}
exec(compile(ast.Module([n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[]), str(access_path), 'exec'), namespace)

semantic_path = ROOT / 'server/sli/semantic/investigation_cases.py'
parsed = ast.parse(semantic_path.read_text(encoding='utf-8'))
semantic = {'Any': Any, 'UUID': UUID}
exec(compile(ast.Module([n for n in parsed.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in {'InvestigationCaseError', '_case_identity', '_case_row', 'add_note'}], type_ignores=[]), str(semantic_path), 'exec'), semantic)
class Cursor:
    def __init__(self, connection): self.connection = connection
    def __enter__(self): return self
    def __exit__(self, *error): pass
    def execute(self, sql, params):
        self.sql = sql
        self.params = params
        self.connection.statements.append(' '.join(sql.split()))
        if self.connection.fail_audit and sql.startswith('insert into investigation_audit'):
            raise RuntimeError('synthetic_audit_failure')
    def fetchone(self):
        if self.sql.lstrip().startswith('insert into investigation_notes'):
            return {'id': 41, 'body': self.params[1], 'created_by': self.params[2], 'created_at': '2026-11-05 01:02:03.123456+00:00'}
        return {'id': 12}
    def fetchall(self): return []
class Connection:
    def __init__(self, fail_audit=False): self.statements=[]; self.fail_audit=fail_audit; self.outcome=None
    def __enter__(self): return self
    def __exit__(self, kind, error, tb): self.outcome='rollback' if kind else 'commit'
    def cursor(self): return Cursor(self)

capability = []
D = lambda id: {'kind':'domain','id':id}
S = lambda id: {'kind':'server','id':id}
C = lambda value: {'kind':'channel','value':value}
policy = lambda effect, scope: {'capability_key':'investigations.manage','effect':effect,'scope_json':scope}
all_scope = {'kind':'all'}
cases = [
 ('global_no_evidence',True,False,[],[]),
 ('global_empty_group',True,False,[],[[]]),
 ('scoped_no_evidence',False,False,[policy('allow',{'kind':'domain','ids':[1]})],[]),
 ('mixed_all_groups',False,False,[policy('allow',{'kind':'server','ids':[2]}),policy('allow',{'kind':'channel','values':[' Security ']})],[[D(1),S(2)],[C('Security')]]),
 ('typed_uncovered',False,False,[policy('allow',{'kind':'domain','ids':[1]})],[[D(1),S(2)],[D(9)]]),
 ('deny_other_alternative',True,False,[policy('deny',{'kind':'server','ids':[2]})],[[D(1),S(2)]]),
 ('deny_other_object',True,False,[policy('deny',{'kind':'server','ids':[9]})],[[D(1),S(2)]]),
 ('global_deny',True,False,[policy('deny',all_scope)],[]),
 ('invalid_deny',True,False,[policy('deny',{'kind':'server','ids':[True]})],[[D(1)]]),
 ('invalid_allow',False,False,[policy('allow',{'kind':'domain','ids':[]})],[[D(1)]]),
 ('owner_bypass',False,True,[policy('deny',all_scope)],[[]]),
 ('python_control_channel',False,False,[policy('allow',{'kind':'channel','values':['\x1cSecurity\x1f']})],[[C('Security')]]),
 ('invalid_control_channel_deny',True,False,[policy('deny',{'kind':'channel','values':['\x1c']})],[[C('Security')]]),
 ('large_integer_deny_nonmatch',True,False,[policy('deny',{'kind':'server','ids':[10**30]})],[[S(2)]]),
 ('null_global_allow',False,False,[policy('allow',None)],[[D(1)]]),
]
for name,glob,owner,raw,groups in ([] if body_only else cases):
    policies=[]
    for row in raw:
        normalized,error=namespace['normalize_capability_scope'](row['scope_json'])
        policies.append({'capability_key':row['capability_key'],'effect':row['effect'],'scope':normalized,'valid':error is None})
    access={'platform_owner':owner,'capabilities':['investigations.manage'] if glob else [],'capability_policies':policies}
    actual=namespace['capability_decision_for_resource_groups'](access,'investigations.manage',resource_groups=groups)
    capability.append({'name':name,'global':glob,'owner':owner,'policies':raw,'groups':groups,'allowed':actual['allowed'],'reason':actual['reason']})

grant = lambda scope,actions=['start_case'],fields=[]: {'scope':scope,'allowed_actions':actions,'field_categories':fields}
report = []
report_cases = [
 ('empty_global',[grant(all_scope)],[],[]),
 ('empty_scoped',[grant({'kind':'domain','ids':[1]})],[],[]),
 ('unresolved',[grant(all_scope)],[[]],[]),
 ('all_evidence',[grant({'kind':'domain','ids':[1]})],[[D(1),S(2)],[D(9)]],[]),
 ('atomic_fields',[grant({'kind':'domain','ids':[1]},fields=['basic']),grant({'kind':'domain','ids':[2]},fields=['sensitive']),grant(all_scope,actions=['view'],fields=['sensitive'])],[[D(1)]],['sensitive']),
 ('atomic_allowed',[grant({'kind':'domain','ids':[2]},fields=['sensitive'])],[[D(2)]],['sensitive']),
 ('generic_domain',[grant({'mode':'restricted','clauses':[{'collection_scope_ids':['ad-domain:1']}]})],[[D(1)]],[]),
 ('generic_missing_device',[grant({'mode':'restricted','clauses':[{'device_ids':['server:2']}]})],[[S(2)]],[]),
 ('generic_all',[grant({'mode':'all'})],[],[]),
 ('invalid_generic',[grant({'mode':'all','unknown':[]})],[[D(1)]],[]),
 ('cross_alternatives',[grant({'mode':'restricted','clauses':[{'device_ids':['server:2'],'collection_scope_ids':['ad-domain:1']}]})],[[D(1),S(2)]],[]),
 ('legacy_integer_coercion',[grant({'kind':'domain','ids':['2',True,1.9]})],[[D(2)]],[]),
 ('legacy_invalid_member',[grant({'kind':'domain','ids':[1,'invalid']})],[[D(1)]],[]),
 ('metadata_python_codepoints',[grant({'mode':'all','decision_id':'😀'*256})],[],[]),
 ('metadata_python_whitespace',[grant({'mode':'all','decision_id':'\x1c'})],[],[]),
]
for name,grants,groups,fields in ([] if body_only else report_cases):
    access={'reports':[{'report_key':'cases.workspace','allowed':True,'grants':grants}]}
    actual=namespace['report_action_decision'](access,'cases.workspace','start_case',resource_groups=groups,required_field_categories=fields)
    report.append({'name':name,'grants':grants,'groups':groups,'fields':fields,'allowed':actual['allowed'],'reason':actual['reason']})

body=[]
body_inputs = ['null','false','0','0.0','[]','{}','true','42','1e0','1.0','1e16','1e-5','1e15','[null,true,1e0]','{"a":"x"}','["a\'b"]','["\\u0001\\u00a0"]',json.dumps('\x1c '+'😀'*4001+' \x1f')]
body_inputs += [r'["\ud800"]', r'["\udfff"]', r'{"\ud800":"\udfff"}',
    r'[{"nested":["x\ud800y","\ud83d\ude00"]}]',
    r'{"a":1,"a":2}', r'{"a":1,"b":2,"a":3}',
    r'[{"a":1,"b":{"x":0,"y":1,"x":2},"a":3}]',
    r'{"a":1,"b":2,"\u0061":3}', r'{"\ud800":1,"b":2,"\ud800":3}',
    r'["\\ud800","\b\f\n\r\t\/\\\""]',
    '[' + json.dumps('a'*3994 + '\ud800') + ']',
    '[' + json.dumps('a'*3997 + '😀\ud800') + ']']
for raw in body_inputs:
    connection=Connection(); semantic['connect']=lambda:connection
    try:
        actual=semantic['add_note'](investigation_id='12',body=str(json.loads(raw) or ''),actor='analyst')
        body.append({'raw':raw,'clean':actual['body'],'error':None})
    except semantic['InvestigationCaseError'] as error:
        body.append({'raw':raw,'clean':None,'error':error.code})

mutations=[]
for fail in ([] if body_only else [False,True]):
    connection=Connection(fail); semantic['connect']=lambda:connection
    try: semantic['add_note'](investigation_id='12',body=' note ',actor='analyst')
    except RuntimeError: pass
    mutations.append({'fail_audit':fail,'statements':connection.statements,'transaction':connection.outcome})

out=Path(__file__).parent/'Fixtures'/'source-vectors.json'
fixture = json.loads(out.read_text(encoding='utf-8')) if body_only else {'source_commit':'ddce909d0ddebe43a670e63c85df369e0bd16f17','mode':'AST-selected frozen functions; stdlib scope; fake DB only, no runtime SQL','capability':capability,'report':report,'source_mutation':mutations}
fixture['body'] = body
out.write_text(json.dumps(fixture,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'capability':len(capability),'report':len(report),'body':len(body),'source_mutation':len(mutations),'out':str(out)}))
