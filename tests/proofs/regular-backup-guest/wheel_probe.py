"""Bound and classify the guest's exact pinned Python wheel import."""

from pathlib import Path
import subprocess
import sys
import tempfile


AUDIT_MODULES = {
    "psycopg": "pure",
    "psycopg.pq": "pq_dispatch",
    "psycopg_binary.pq": "binary_pq",
    "psycopg_binary._psycopg": "binary_extension",
    "_ssl": "stdlib_ssl",
    "_hashlib": "stdlib_hashlib",
}
IMPORT_ERRORS = {
    "elf_mapping_denied", "elf_stack_denied", "elf_missing_zlib", "elf_missing_gcc_runtime",
    "elf_missing_cpp_runtime", "elf_library_missing", "elf_symbol_version", "elf_format",
    "python_module_missing", "unclassified_import_error",
}
WAIT_CHANNELS = {
    "futex_wait_queue": "import_wait_futex",
    "futex_wait": "import_wait_futex",
    "wait_for_random_bytes": "import_wait_entropy",
    "io_schedule": "import_wait_io",
    "wait_on_page_bit_common": "import_wait_io",
    "0": "import_wait_running_or_hidden",
}
CHILD_MARKERS = IMPORT_ERRORS | {"import_started", "import_returned", "import_contract_refused", "binary_imported"} | {
    f"{module}_{stage}" for module in AUDIT_MODULES.values() for stage in ("enter", "loader")
}


def import_failure(error):
    cause = error
    for _ in range(4):
        if cause.__cause__ is None:
            break
        cause = cause.__cause__
    detail = str(cause)
    if "failed to map segment from shared object" in detail:
        return "elf_mapping_denied"
    if "cannot enable executable stack" in detail:
        return "elf_stack_denied"
    if "cannot open shared object file" in detail:
        for name, marker in (("libz.so.1", "elf_missing_zlib"), ("libgcc_s.so.1", "elf_missing_gcc_runtime"),
                             ("libstdc++.so.6", "elf_missing_cpp_runtime")):
            if detail.startswith(name + ":"):
                return marker
        return "elf_library_missing"
    if "undefined symbol" in detail or ("version " in detail and " not found" in detail):
        return "elf_symbol_version"
    if "ELF" in detail:
        return "elf_format"
    if isinstance(cause, ModuleNotFoundError):
        return "python_module_missing"
    return "unclassified_import_error"


def child(vendor):
    seen = set()

    def audit(event, args):
        if event == "import" and args[0] in AUDIT_MODULES:
            step = AUDIT_MODULES[args[0]] + ("_loader" if args[1] else "_enter")
            if step not in seen:
                seen.add(step)
                print(step, flush=True)

    sys.addaudithook(audit)
    sys.path.insert(0, vendor)
    print("import_started", flush=True)
    try:
        import psycopg
    except ImportError as error:
        print(import_failure(error), flush=True)
        return 1
    print("import_returned", flush=True)
    if psycopg.__version__ != "3.3.4" or psycopg.pq.__impl__ != "binary":
        print("import_contract_refused", flush=True)
        return 1
    print("binary_imported", flush=True)
    return 0


def wait_marker(pid):
    try:
        with Path(f"/proc/{pid}/wchan").open(encoding="ascii") as handle:
            return WAIT_CHANNELS.get(handle.read(128).strip(), "import_wait_unclassified")
    except (OSError, UnicodeError):
        return "import_wait_unavailable"


def probe(vendor):
    def emit(marker):
        print("SLI_REGULAR_BACKUP_PROOF_DEPENDENCY " + marker, flush=True)

    with tempfile.TemporaryFile() as stream:
        try:
            process = subprocess.Popen((sys.executable, "-I", "-B", __file__, "--child", vendor),
                                       stdout=stream, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        except OSError:
            emit("import_child_start_refused")
            return 1
        try:
            status = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            emit("import_child_timeout")
            emit(wait_marker(process.pid))
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                emit("import_child_stop_unconfirmed")
            status = None
        stream.seek(0)
        markers = [line for line in stream.read(4096).decode("ascii", errors="replace").splitlines()
                   if line in CHILD_MARKERS]
    for marker in dict.fromkeys(markers):
        emit(marker)
    if status == 0 and markers.count("binary_imported") == 1:
        emit("import_child_exit_zero")
        return 0
    if status is not None:
        emit("import_child_signal" if status < 0 else "import_child_exit_error")
    return 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        raise SystemExit(child(sys.argv[2]))
    if len(sys.argv) == 2:
        raise SystemExit(probe(sys.argv[1]))
    raise SystemExit(2)
