# Disposable regular-backup guest proof

This source-only proof exercises the backup code at `1b5daf4e66640b7390105b4b5345332deca6f9ce`. It requires an official, independently authenticated Debian 13 generic amd64 cloud image as a standalone QCOW2 file. The generic image uses the standard Debian kernel. An authenticated SHA-512 for an immutable build is required before a CI workflow can pin the boot image. [Debian Cloud images](https://wiki.debian.org/Cloud)

The launcher takes an already authenticated digest as input. Establish it through signed release metadata with an authorized Debian image signing key, or an independently verified boot image and attested digest. Computing a digest from the image you just downloaded only checks consistency. No network fetch, package manager, privileged host operation, or upload is part of this bootstrap.

## Run on an unprivileged Linux host

Prepare Git, Python 3.11 or later, QEMU, `qemu-img`, util-linux with `sfdisk`, and `xorriso`. Put these two unmodified wheels in a local directory.

- `psycopg-3.3.4-py3-none-any.whl` uses the hash already pinned in the product's native runtime lock. [PyPI wheel details](https://pypi.org/project/psycopg/3.3.4/#psycopg-3.3.4-py3-none-any.whl)
- `psycopg_binary-3.3.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` matches the Debian guest's CPython 3.13 and bundles libpq. [PyPI wheel details](https://pypi.org/project/psycopg-binary/3.3.4/#psycopg_binary-3.3.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl)

```sh
python3 -B tests/proofs/regular-backup-guest/boot_proof.py \
    --source "$PWD" \
    --wheelhouse "$WHEELHOUSE" \
    --image "$DEBIAN_QCOW2" \
    --image-sha512 "$AUTHENTICATED_SHA512"
```

The launcher checks the boot image and wheel digests, creates a read-only NoCloud seed and a writable overlay for the read-only boot base, and starts QEMU with `-nic none`. The other two virtual disks come from new regular files. Only the guest formats and mounts its fixture disks. The seed contains the exact commit's `deploy/linux` tree, the proof, and the checked wheels. Host checkout files, mounts, block devices, and credentials are outside the guest.

The two partitions of one guest disk have different `st_dev` values. The source rejects that destination both when selecting it and when starting capture with a previously saved path. The other virtual disk must receive one archive verified by the source's two manifests and terminal receipt. Scheduled capture remains off and the rollback marker remains intact. The launcher requires the exact result and one terminal marker, normal QEMU exit, and an unchanged boot base. The guest proof is limited to 120 seconds and the VM invocation to 360 seconds.

PostgreSQL dump bytes, the SQL capacity lookup, host admission and the companion are synthetic. The installed service, real `pg_dump` and restore, timer activation, and release rollback need their own verification. Earlier namespace validation covered lazy detach on tmpfs. [Namespace validation](https://github.com/sli-project/sli/actions/runs/45181551490/job/137716330907)
