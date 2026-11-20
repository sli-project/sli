import pytest

from server.sli.events.evsearch_contract import ContractError
from server.sli.events.evsearch_snapshot import SnapshotError
from tests.unit.test_evsearch_grouping import MID, arguments, event, search, start


def test_members_are_exact_frozen_authorized_and_paged():
    store, page, args, _ = start([(2, MID, event()), (3, MID, event()), (4, MID, event())])
    assert callable(getattr(store, 'members', None))
    key = page.items[0]['group_key']
    first = store.members(page.execution_id, group_key=key, **args)
    assert [r['event_db_id'] for r in first.items] == [2, 3]
    assert first.has_more
    assert first.items[0]['source_store'] == 'postgres'
    first.items[0]['fields']['action'] = 'changed'
    second = store.members(page.execution_id, group_key=key, cursor=first.next_cursor, **args)
    assert [r['event_db_id'] for r in second.items] == [4]
    assert not second.has_more
    assert store.members(page.execution_id, group_key=key, **args).items[0]['fields']['action'] != 'changed'
    with pytest.raises(SnapshotError):
        store.members(page.execution_id, group_key=key, **{**args, 'owner_id': 2})


def test_members_cursor_is_bound_to_group_and_not_a_group_page_cursor():
    store, page, args, _ = start([(i, MID, event(reason=str(i // 3))) for i in range(1, 8)], args=arguments(search=search(sort="count_desc", page_size=2)))
    assert callable(getattr(store, 'members', None))
    key = next(g['group_key'] for g in page.items if g['count'] == 3)
    first = store.members(page.execution_id, group_key=key, **args)
    assert first.next_cursor
    other = next(g['group_key'] for g in page.items if g['group_key'] != key)
    with pytest.raises(ContractError, match='invalid_cursor'):
        store.members(page.execution_id, group_key=other, cursor=first.next_cursor, **args)
    with pytest.raises(ContractError, match='invalid_cursor'):
        store.page(page.execution_id, cursor=first.next_cursor, **args)


def test_runtime_context_frozen_in_budgeted_snapshot_and_foreign_denied():
    store, page, args, _ = start([(1, MID, event())], retention_boundary=MID)
    assert callable(getattr(store, 'execution_context', None))
    context = store.execution_context(page.execution_id, owner_id=1)
    assert context['request']['period'] == args['search'].period.as_request()
    assert context['retention_boundary'] == MID.isoformat()
    with pytest.raises(SnapshotError):
        store.execution_context(page.execution_id, owner_id=2)


def test_members_rechecks_revision_and_expiration():
    store, page, args, _ = start([(1, MID, event())])
    assert callable(getattr(store, 'members', None))
    with pytest.raises(SnapshotError, match='snapshot_invalidated'):
        store.members(page.execution_id, group_key=page.items[0]['group_key'], **{**args, 'revision': 'new'})
