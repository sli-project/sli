from datetime import timedelta
import pytest
from server.sli.agent_ingest import receive_packet
from sli_agent.envelope import make_packet,digest
from sli_agent.modules import HeartbeatModule
from tests.unit.test_agent_ingest import Ledger,NOW,AGENT,HOST,context

class RecoveryLedger(Ledger):
    def __init__(self):
        super().__init__(); self.observed=[]; self.authorized=None; self.accepted=[]
    def recovery_boundary(self, identity, envelope, previous, now):
        d=(digest(envelope),digest(previous) if previous else None,identity.get('key_fingerprint'))
        self.observed.append(d)
        return '1' if self.authorized==d else None
    def accept_recovery(self, observation_id, envelope, now):
        self.accepted.append(observation_id)

def setup(context):
    _,identity,key=context; identity['key_fingerprint']='a'*64
    ledger=RecoveryLedger(); return ledger,identity,key

def packet(key, sequence, previous=None):
    sample=HeartbeatModule(HOST).collect(previous,now=NOW)
    # Native heartbeat cursor is the sequence, even when the restored server lacks history.
    sample=__import__('dataclasses').replace(sample,cursor_before={'strategy':'record_id','token':str(sequence-1) if sequence>1 else ''},cursor_after={'strategy':'record_id','token':str(sequence)})
    return make_packet(key,agent_id=AGENT,sequence=sequence,sample=sample,now=NOW)

def receive(c,value,now=NOW):
    ledger,identity,key=c
    return receive_packet(ledger,identity=identity,public_key=key.public_key(),value=value,now=now)

def test_explicit_boundary_recovers_cursor_and_sequence_without_rewriting(context):
    c=setup(context); ledger,identity,key=c
    first=packet(key,1); assert receive(c,first)['status']=='committed'
    boundary=packet(key,5)
    assert receive(c,boundary)['error_code']=='agent_sequence_gap'
    assert ledger.observed
    ledger.authorized=ledger.observed[-1]
    assert receive(c,boundary)['status']=='committed'
    assert ledger.accepted==['1']
    assert [r['envelope']['sequence'] for r in ledger.rows]==[1,5]
    assert receive(c,boundary)['status']=='duplicate'
    assert len(ledger.accepted)==1
    assert receive(c,packet(key,6))['status']=='committed'
    assert receive(c,packet(key,3))['status']=='rejected'

@pytest.mark.parametrize('change',['key','packet','previous'])
def test_boundary_authorization_cannot_be_reused_for_changed_identity(context,change):
    c=setup(context); ledger,identity,key=c; value=packet(key,5)
    receive(c,value); assert ledger.observed
    ledger.authorized=ledger.observed[-1]
    if change=='key': identity['key_fingerprint']='b'*64
    elif change=='packet': value=packet(key,5)
    else: assert receive(c,packet(key,1))['status']=='committed'
    assert receive(c,value)['status']=='retry_later'
    assert not ledger.accepted

def test_recovery_keeps_quota_and_replay_window(context):
    c=setup(context); ledger,_,key=c; value=packet(key,5)
    receive(c,value); assert ledger.observed; ledger.authorized=ledger.observed[-1]
    ledger.quota='agent_inbox_storage_bytes_limit'
    assert receive(c,value)['error_code']==ledger.quota
    assert not ledger.accepted and not ledger.rows
    ledger.quota=None
    assert receive(c,value,now=NOW+timedelta(days=8))['error_code']=='agent_replay_window'
    assert not ledger.accepted
    assert receive(c,value)['status']=='committed'


def test_midcycle_snapshot_recovery_never_publishes_partial_cycle(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from tests.unit.test_agent_snapshot_stream import Ledger as SnapshotLedger, packets, stream, FRAGMENT_BYTES
    from server.sli.agents.snapshot_consumer import validate_cycle
    class RecoverableSnapshot(SnapshotLedger):
        recovery_boundary=RecoveryLedger.recovery_boundary
        accept_recovery=RecoveryLedger.accept_recovery
    ledger=RecoverableSnapshot()
    ledger.observed=[];ledger.authorized=None;ledger.accepted=[]
    ledger.identity['key_fingerprint']='a'*64
    key=ec.generate_private_key(ec.SECP256R1())
    values=packets(stream(tmp_path,size=FRAGMENT_BYTES*3),key)
    assert len(values)>2
    boundary=values[1]
    assert ledger.receive(boundary,key)['error_code']=='agent_sequence_gap'
    ledger.authorized=ledger.observed[-1]
    assert ledger.receive(boundary,key)['status']=='committed'
    for value in values[2:]: assert ledger.receive(value,key)['status']=='committed'
    cycle=next(iter(ledger.cycles.values()))
    assert validate_cycle(cycle,ledger.rows) is False
    assert cycle['transport_state']=='pending'
