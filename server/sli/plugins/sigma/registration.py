"""Dormant Sigma contributions, with no policy, source or scheduling side effects."""
from __future__ import annotations


def register(contribution):
    contribution.hooks.update({
        "health": _health,
        "semantic_capabilities": _semantic_capabilities,
        "chain_candidates": _chain_candidates,
        "evaluate_process_chain": _evaluate_process_chain,
    })


def _health():
    return True


def _semantic_capabilities():
    return {"sli.sigma.detection-match.v1": "1.0.0"}


def _chain_candidates():
    from server.sli.sigma.process_chain import CHAIN_ID, CHAIN_VERSION

    return ({"chain_id": CHAIN_ID, "chain_version": CHAIN_VERSION,
             "lifecycle_state": "draft"},)


def _evaluate_process_chain(*args, **kwargs):
    from server.sli.sigma.process_chain import evaluate_process_chain

    return evaluate_process_chain(*args, **kwargs)
