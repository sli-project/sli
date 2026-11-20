#!/usr/bin/env bash
# Run on the connected operator Docker host; never on the offline target or CI runner.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
kit=$(cd "$(dirname "$0")" && pwd)
python=${SLI_RELEASE_PYTHON:-python3.14}
args=()
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --internal-test-build) args+=(--internal-test-build); shift ;;
    --output) test "$#" -ge 2 && test -n "$2"; output=$2; shift 2 ;;
    *) printf '%s\n' 'Usage: build_offline_kit.sh [--output NEW_DIRECTORY] [--internal-test-build]' >&2; exit 2 ;;
  esac
done
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
if [ ! -f "$kit/source/tools/release_artifacts.py" ]; then
  root=$(cd "$kit/../.." && pwd)
  if [ ! -f "$root/tools/release_artifacts.py" ]; then
    printf '%s\n' 'Run from a Git checkout or a prepared kit containing source/tools/release_artifacts.py.' >&2
    exit 1
  fi
  # Bootstrap the same exact-SHA inputs as CI, without requiring GitHub credentials.
  sha=$(git -C "$root" rev-parse HEAD)
  version=$(git -C "$root" show "$sha:VERSION")
  output=${output:-"$root/../sli-kit-$version-${sha:0:12}"}
  test ! -e "$output"
  git -C "$root" show "$sha:requirements.lock.txt" > "$work/requirements.lock.txt"
  "$python" -m venv "$work/venv"
  python="$work/venv/bin/python"
  "$python" -m pip install --disable-pip-version-check --no-deps -r "$work/requirements.lock.txt"
  "$python" -m pip check
  "$python" "$root/tools/release_artifacts.py" prepare --root "$root" \
    --sha "$sha" --version "$version" --output "$output" "${args[@]}"
  kit=$(cd "$output" && pwd)
  "$python" "$kit/source/tools/release_artifacts.py" bundle-host-libs --kit "$kit" "${args[@]}"
else
  # A prepared CI kit builds in place; never silently redirect it to another tree.
  test -z "$output"
fi
host_python=$("$python" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
export PYTHONPATH="$kit/host-libs/$host_python:$kit/source${PYTHONPATH:+:$PYTHONPATH}"
# Validate the release plugin set before pulling or building any images.
"$python" "$kit/source/tools/release_artifacts.py" check-source --kit "$kit" "${args[@]}"
readarray -t inputs < <("$python" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["version"]); print(d["source_commit"]); print(d["source_date_epoch"])' "$kit/release-inputs.json")
version=${inputs[0]}
sha=${inputs[1]}
export SOURCE_DATE_EPOCH=${inputs[2]}
mkdir -p "$kit/images" "$kit/inventories"
# Resolve base tags once. The digest lock is retained for a repeat build.
if [ ! -f "$kit/inventories/base-images.lock" ]; then
  for reference in node:22-bookworm-slim python:3.14.6-slim-bookworm; do
    docker pull --platform linux/amd64 "$reference" >&2
    docker image inspect --format '{{index .RepoDigests 0}}' "$reference"
  done > "$work/base-images.lock"
  mv "$work/base-images.lock" "$kit/inventories/base-images.lock"
fi
readarray -t bases < "$kit/inventories/base-images.lock"
test "${#bases[@]}" -eq 2
for base in "${bases[@]}"; do
  [[ "$base" =~ @sha256:[0-9a-f]{64}$ ]]
done
# Keep the exported SHA inputs immutable. Only the temporary Dockerfile pins bases
# and disables dependency resolution outside the checked-in Python lock.
sed -e "s|^FROM node:22-bookworm-slim AS frontend-build$|FROM ${bases[0]} AS frontend-build|" \
    -e "s|^FROM python:3.14.6-slim-bookworm$|FROM ${bases[1]}|" \
    -e 's|pip install --no-cache-dir -r requirements.lock.txt|pip install --no-cache-dir --no-deps -r requirements.lock.txt|' \
    "$kit/source/deploy/linux/Dockerfile" > "$work/Dockerfile"
grep -Fxq "FROM ${bases[0]} AS frontend-build" "$work/Dockerfile"
grep -Fxq "FROM ${bases[1]}" "$work/Dockerfile"
cp "$kit/source/deploy/linux/Dockerfile.dockerignore" "$work/Dockerfile.dockerignore"
docker build --platform linux/amd64 --build-arg "SLI_VERSION=$version" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --label "org.opencontainers.image.revision=$sha" \
  -f "$work/Dockerfile" -t "sli-release:$version" "$kit/source"
for name in server postgres clickhouse; do
  case "$name" in
    server) reference="sli-release:$version" ;;
    postgres) reference=postgres:18.6-bookworm ;;
    clickhouse) reference=clickhouse/clickhouse-server:25.8 ;;
  esac
  if [ "$name" != server ]; then docker pull --platform linux/amd64 "$reference"; fi
  docker image save --output "$work/$name.tar" "$reference"
  "$python" "$kit/source/tools/release_artifacts.py" compact-image \
    --input "$work/$name.tar" --output "$kit/images/$name.tar"
done
# Inventory OS packages without starting the application or mounting host data.
docker run --rm --network none --entrypoint dpkg-query "sli-release:$version" \
  -W '-f=${Package}\t${Version}\n' > "$kit/inventories/os-packages.tsv"
"$python" "$kit/source/tools/release_artifacts.py" finalize-images --kit "$kit" "${args[@]}"
"$python" "$kit/source/tools/release_artifacts.py" finalize-evaluation --kit "$kit" "${args[@]}"
sha256sum "$kit/KIT_INVENTORY.json"
printf '%s\n' "Evaluation kit complete: unsigned / для оценки, без подписи. Read START_HERE.md. Offline owner signing is required for a signed delivery."
