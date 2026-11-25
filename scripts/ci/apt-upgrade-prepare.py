"""Reuse the pinned rollback VM and receipt proof for an APT-only transition."""
from pathlib import Path
import sys


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("pinned harness anchor changed: " + old.splitlines()[0])
    return source.replace(old, new, 1)


vm, scenario, output = map(Path, sys.argv[1:4])
driver = vm.read_text()
driver = replace_once(
    driver,
    "        ca-certificates curl e2fsprogs sudo >>",
    "        ca-certificates curl e2fsprogs sudo gnupg >>",
)
driver = replace_once(
    driver,
    "    stage=upgrade_and_rollback\n",
    "    stage=apt_upgrade\n",
)
driver = replace_once(
    driver,
    "    printf 'P1_EVIDENCE entering=%s\\n' \"$stage\"\n"
    "    read -r commit checksum <\"$input/candidate.pin\"\n",
    "    printf 'P1_EVIDENCE entering=%s\\n' \"$stage\"\n"
    "    read -r commit checksum <\"$input/candidate.pin\"\n"
    "    [[ $checksum == b3d5b8eb293bebee5142ffd9717620bf3491361bc445dc96bbc35171178177bd ]]\n",
)
driver = replace_once(
    driver,
    '                sed \'s/^/P1_EVIDENCE /\'\n        fi\n',
    '                sed \'s/^/P1_EVIDENCE /\'\n'
    '            grep -E \'^P1_EVIDENCE apt_[A-Za-z_]+=\' "$scenario_log" || true\n'
    '        fi\n',
)
driver = replace_once(
    driver,
    'cp "$GITHUB_WORKSPACE/scripts/ci/p1-native-410-411-rollback.sh" input/\n'
    'cp "$GITHUB_WORKSPACE/scripts/ci/p1-native-rollback-vm.sh" input/',
    'cp "$RUNNER_TEMP/apt-proof/p1-native-410-411-rollback.sh" input/\n'
    'cp "$0" input/p1-native-rollback-vm.sh\n'
    'cp "$GITHUB_WORKSPACE/scripts/ci/apt-upgrade-410-411.sh" input/\n'
    'cp -R "$RUNNER_TEMP/apt-tools" input/',
)
(output / "vm.sh").write_text(driver)

proof = scenario.read_text()
start = "printf 'P1_STEP candidate_install_entered\\n'\n"
finish = "\nverify_transition() {\n"
assert proof.count(start) == proof.count(finish) == 1
before, tail = proof.split(start)
_, verify = tail.split(finish)
end = "\nverify_transition upgraded\n"
assert verify.count(end) == 1
verifier, _ = verify.split(end)
verifier = replace_once(
    verifier,
    '"backup_id": identifier, "backup_manifest_sha256": expected, "data": present,',
    '"backup_id": identifier, "backup_manifest_sha256": expected,\n'
    '    "checkpoint_verification": mode, "verification_receipt_sha256": '
    'hashlib.sha256((point / f"{mode}-verified.json").read_bytes()).hexdigest(),'
    ' "data": present,',
)
(output / "p1-native-410-411-rollback.sh").write_text(
    before + 'source /mnt/p1-input/apt-upgrade-410-411.sh\n'
    + finish + verifier + end
)
