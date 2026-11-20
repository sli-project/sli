from __future__ import annotations

import csv
import io

import pytest

from server.sli.reporting.v2.definition import Column, csv_from_columns


@pytest.mark.parametrize("prefix", ["", " ", "  ", "\t", "\r", "\n", " \t", "\u00a0"])
@pytest.mark.parametrize("formula", ["=1+1", "+1+1", "-1+1", "@SUM(1,1)"])
def test_csv_neutralises_formulas_after_leading_whitespace(prefix, formula):
    value = prefix + formula
    document = csv_from_columns((Column("value", "Value"),), [{"value": value}])

    assert list(csv.reader(io.StringIO(document))) == [["Value"], ["'" + value]]


@pytest.mark.parametrize("value,expected", [
    (None, ""), (0, "0"), (42, "42"), ("", ""),
    ("Synthetic value", "Synthetic value"), ("  Synthetic value", "  Synthetic value"),
    ("\tSynthetic value", "'\tSynthetic value"),
    ("\rSynthetic value", "'\rSynthetic value"),
    ("\nSynthetic value", "'\nSynthetic value"),
    ("'=1+1", "'=1+1"),
])
def test_csv_preserves_values_and_escapes_leading_controls(value, expected):
    document = csv_from_columns((Column("value", "Value"),), [{"value": value}])

    assert list(csv.reader(io.StringIO(document))) == [["Value"], [expected]]


def test_csv_neutralises_joined_values_and_display_labels():
    columns = (
        Column("values", "Values"),
        Column("state", "State", labels={"synthetic": "  =1+1"}),
    )
    document = csv_from_columns(columns, [{"values": ["  =1+1", "safe"], "state": "synthetic"}])

    assert list(csv.reader(io.StringIO(document))) == [["Values", "State"], ["'  =1+1, safe", "'  =1+1"]]
