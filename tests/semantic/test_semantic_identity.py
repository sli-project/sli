import pytest

from server.sli.semantic.semantic_identity import parse_exact_domain_sid_partition


def test_parse_exact_domain_sid_partition_accepts_canonical_account_identity() -> None:
    assert parse_exact_domain_sid_partition(
        "domain:7|account_sid:S-1-5-21-100-200-300-400"
    ) == {
        "domain": "7",
        "account_sid": "S-1-5-21-100-200-300-400",
    }


@pytest.mark.parametrize(
    "partition_key",
    (
        "domain:7|account_sid:S-1-5-21-100-200-300-400|junk:x",
        "domain:7|account_sid:S-1-5-21-100-200-300-400|account_sid:S-1-5-21-100-200-300-401",
        "domain:7|account_sid:S-1-5-21-100-200-300-40\N{ARABIC-INDIC DIGIT FOUR}",
        "domain:+1|account_sid:S-1-5-21-100-200-300-400",
        "domain:01|account_sid:S-1-5-21-100-200-300-400",
        "domain: 1|account_sid:S-1-5-21-100-200-300-400",
        "domain:\N{ARABIC-INDIC DIGIT ONE}|account_sid:S-1-5-21-100-200-300-400",
        "domain:0|account_sid:S-1-5-21-100-200-300-400",
    ),
)
def test_parse_exact_domain_sid_partition_rejects_noncanonical_components(
    partition_key: str,
) -> None:
    assert parse_exact_domain_sid_partition(partition_key) is None
