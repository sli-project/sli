from unittest.mock import Mock
import pytest
from server.api.routes import agents
from http import HTTPStatus

class Handler:
    def __init__(self, *, authenticated=True, owner=True, mutation=True, manage=False):
        self.authenticated, self.owner, self.mutation = authenticated, owner, mutation
        self.manage = manage
        self._principal = {"type": "session", "id": 1, "role": "admin"}
        self.connection = object()
        self.headers = {}
        self.body = {}
        self.responses = []

    def _require_access(self, role):
        if not self.authenticated:
            self._send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
        return self.authenticated

    def _access_decision(self):
        return {"platform_owner": self.owner}

    def _require_capability(self, capability):
        assert capability == "access.manage"
        if not self.manage:
            self._send_json({"error": "capability_required"}, HTTPStatus.FORBIDDEN)
        return self.manage

    def _authorize_mutation(self, *, required_role):
        if not self.mutation:
            self._send_json({"error": "cross_origin_request_rejected"}, HTTPStatus.FORBIDDEN)
        return self.mutation

    def _read_json_body(self, **kwargs):
        self.body_options = kwargs
        return self.body

    def _send_json(self, result, status=HTTPStatus.OK, *, headers=None):
        self.responses.append((result, status, headers))

from server.sli.agents import sequence_recovery
from server.sli.agents.ca import AgentError

PATH='/api/v1/admin/agents/sequence-recovery'
@pytest.mark.parametrize('method',['GET','POST'])
@pytest.mark.parametrize('options',[{'authenticated':False},{'owner':False,'manage':True},{'owner':False},{'mutation':False}])
def test_recovery_requires_real_owner_and_csrf(monkeypatch,method,options):
    if method=='GET' and options=={'mutation':False}: pytest.skip('GET is read only')
    execute=Mock();monkeypatch.setattr(agents,'_execute',execute)
    handler=Handler(**options)
    handled=agents.try_handle_get(handler,PATH,{'agent_id':['id']}) if method=='GET' else agents.try_handle_post(handler,PATH)
    assert handled
    execute.assert_not_called()
    assert handler.responses[-1][1] in (401,403)

@pytest.mark.parametrize('body',[None,{}, {'observation_id':'1','confirm_loss':False},{'observation_id':'-1','confirm_loss':True},{'observation_id':'1','confirm_loss':True,'extra':True}])
def test_service_invalid_confirmation_never_queries(body):
    cur=Mock()
    with pytest.raises(AgentError):sequence_recovery.authorize(cur,body,actor='session:1',access={'platform_owner':True})
    cur.execute.assert_not_called()

def test_service_no_capability_escalation():
    cur=Mock()
    with pytest.raises(AgentError):sequence_recovery.list_gaps(cur,'id',access={'capabilities':['access.manage']})
    cur.execute.assert_not_called()

@pytest.mark.parametrize('actor',['x'*128,'bad\nactor'])
def test_cli_rejects_invalid_final_actor_before_database(monkeypatch,actor):
    from types import SimpleNamespace
    from server.sli.agents import sequence_recovery_admin as cli
    connect=Mock();monkeypatch.setattr(cli,'connect',connect)
    with pytest.raises(AgentError):cli.run(SimpleNamespace(owner_user_id=1,actor=actor))
    connect.assert_not_called()

def test_owner_route_calls_service_with_exact_body(monkeypatch):
    handler=Handler();handler.body={'agent_id':'fixture','observation_ids':['42'],'preview_token':'a'*64,'confirm_loss':True}
    service=Mock(return_value={'status':'authorized','agent_id':'fixture','observation_ids':['42']})
    monkeypatch.setattr(agents.sequence_recovery,'authorize_all',service)
    cursor=object();monkeypatch.setattr(agents,'_execute',lambda h,operation:operation(cursor))
    assert agents.try_handle_post(handler,PATH)
    service.assert_called_once_with(cursor,handler.body,actor='session:1',access={'platform_owner':True})
