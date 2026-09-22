#!/usr/bin/env python3
"""Register a cold-snap Mk4 firmware revision in the coordinator's compatibility
registry (`frostsnap_coordinator/src/coldsnap-mk4-registry.txt`).

    register-mk4-firmware.py <signed-image.bin> <revision-label>
    register-mk4-firmware.py --print <signed-image.bin>
    register-mk4-firmware.py --self-check

THE REGISTRY IS COMPATIBILITY METADATA, NOT PERMISSION TO INSTALL. Registering a
revision only lets this app recognize, name and use a device announcing that
digest. It is not an allowlist, a release authority, a rollback ratchet or a
trust anchor: a locally built Mk4 image signed with the published dev key 0
installs on a device with no entry here, and nothing in this tree can or should
change that.

THE DIGEST. What a cold-snap Mk4 announces in `DeviceSendBody::Announce` is a
SINGLE sha256 over TWO ranges of the image -- [0, 16320) then [16384,
firmware_length) -- i.e. with the 64-byte key-0 signature that sits inside the
header punched out. Source of truth: `coldsnap_firmware::firmware_digest`
(cold-snap `firmware/src/lib.rs:3003-3052`), pinned in
`cold-snap/golden/mk4-staging-vectors.txt`.

That is NOT the digest `ValidatedFirmwareBin::digest()` computes for an ESP32
image (a single sha256 over one contiguous prefix), and NOT the Mk4
bootloader's `fw_check` (sha256 OF the announced digest, a double hash). All
three are different numbers over the same bytes; registering either of the other
two would register a digest no device will ever announce. `--self-check`
reproduces the golden file's `m13-synth-262656` vector so a drift in this script
is caught here rather than as a device that silently stays unrecognized.
"""

import hashlib
import re
import sys
from pathlib import Path

REGISTRY = Path(__file__).resolve().parent.parent / "src" / "coldsnap-mk4-registry.txt"

# Header geometry, from cold-snap `hal/src/lib.rs:298,300` and `hal/src/psram.rs:172`.
FW_HEADER_OFFSET = 16256
FW_LENGTH_FIELD_OFFSET = 24
SIGNATURE_START = 16320  # FW_HEADER_OFFSET + 64, where key 0's signature begins
SIGNATURE_END = 16384  # and where it ends: 64 bytes, punched out of the digest
FW_MIN_BODY_LEN = 262144
FW_BODY_ALIGN = 512

# cold-snap `golden/mk4-staging-vectors.txt`, vector `m13-synth-262656`. The golden
# file carries the reproduction recipe; this is its `announced` column.
GOLDEN_SIZE = 262656
GOLDEN_ANNOUNCED = "33b54101f5ab06c1db9f6a968b4687114926ccac1a5054821e8bbf6e1ab19489"


def announced_digest(image: bytes) -> str:
    """The digest a cold-snap Mk4 announces for `image`."""
    off = FW_HEADER_OFFSET + FW_LENGTH_FIELD_OFFSET
    length = int.from_bytes(image[off : off + 4], "little")
    if length < FW_MIN_BODY_LEN:
        raise SystemExit(f"header firmware_length {length} < FW_MIN_BODY_LEN {FW_MIN_BODY_LEN}")
    if length % FW_BODY_ALIGN:
        raise SystemExit(f"header firmware_length {length} is not a multiple of {FW_BODY_ALIGN}")
    if length > len(image):
        raise SystemExit(f"header firmware_length {length} exceeds the {len(image)}-byte file")
    h = hashlib.sha256()
    h.update(image[0:SIGNATURE_START])
    h.update(image[SIGNATURE_END:length])
    return h.hexdigest()


def self_check() -> None:
    img = bytearray((i * 7 + i // 251) % 256 for i in range(GOLDEN_SIZE))
    img[16280:16284] = GOLDEN_SIZE.to_bytes(4, "little")
    got = announced_digest(bytes(img))
    if got != GOLDEN_ANNOUNCED:
        raise SystemExit(f"self-check FAILED: {got} != golden {GOLDEN_ANNOUNCED}")
    print(f"self-check ok: m13-synth-{GOLDEN_SIZE} announced = {got}")


def upsert(digest: str, label: str) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", label):
        raise SystemExit(f"revision label {label!r} must match [a-z0-9][a-z0-9._-]*")
    lines = REGISTRY.read_text().splitlines()
    entry = f"{digest} {label}"
    out, replaced = [], False
    for line in lines:
        fields = line.split()
        if len(fields) == 2 and not line.startswith("#") and (fields[0] == digest or fields[1] == label):
            if replaced or entry in out:
                continue
            out.append(entry)
            replaced = True
            print(f"updated: {line}  ->  {entry}")
            continue
        out.append(line)
    if not replaced:
        out.append(entry)
        print(f"registered: {entry}")
    REGISTRY.write_text("\n".join(out) + "\n")


def main(argv: list[str]) -> None:
    if argv == ["--self-check"]:
        return self_check()
    if len(argv) == 2 and argv[0] == "--print":
        return print(announced_digest(Path(argv[1]).read_bytes()))
    if len(argv) != 2:
        raise SystemExit(__doc__)
    self_check()
    digest = announced_digest(Path(argv[0]).read_bytes())
    print(f"announced digest: {digest}")
    upsert(digest, argv[1])


if __name__ == "__main__":
    main(sys.argv[1:])
