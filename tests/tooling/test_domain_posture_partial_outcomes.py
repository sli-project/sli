from pathlib import Path


MODULE = Path("scripts/ad_context/DomainPosture.psm1")


def test_domain_posture_reports_each_check_outcome_without_aborting_bundle() -> None:
    source = MODULE.read_text(encoding="utf-8")

    assert "status = \"PASS\"" in source
    assert "status = \"PARTIAL\"" in source
    assert "error_code" in source
    assert "catch {" in source
