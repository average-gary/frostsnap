//! Mk4 artifact loading, DfuSe extraction and pre-transfer validation.
//!
//! Two tiers:
//! * hermetic: synthetic images signed here with the PUBLISHED dev key 0, one
//!   refusal per rule, and every malformed-container shape;
//! * `#[ignore]`d, needs `COLDSNAP_REPO`: the real task-01 artifacts, the
//!   task-05 negative fixtures, a real local build absent from the registry, the
//!   golden digest vector, and verdict agreement with cold-snap's own `checkfw`.
//!   These FAIL (never skip) when the environment is missing:
//!
//! ```text
//! COLDSNAP_REPO="$HOME/repos/cold-snap" \
//!   cargo test --target aarch64-apple-darwin -p frostsnap_coordinator \
//!   --test mk4_firmware_artifacts -- --ignored
//! ```

use frostsnap_coordinator::device_profile::registered_mk4_revision;
use frostsnap_coordinator::mk4_firmware::*;
use frostsnap_coordinator::{FirmwareBin, FirmwareValidationError};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[path = "support/mk4_key0.rs"]
mod mk4_key0;
use mk4_key0::*;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// A DfuSe file the way `micropython/tools/dfu.py` writes one, over arbitrary
/// `(address, bytes)` elements. Callers corrupt the result to probe the parser.
fn dfuse(elements: &[(u32, &[u8])]) -> Vec<u8> {
    let mut tgt = Vec::new();
    for (addr, data) in elements {
        tgt.extend_from_slice(&addr.to_le_bytes());
        tgt.extend_from_slice(&(data.len() as u32).to_le_bytes());
        tgt.extend_from_slice(data);
    }
    let mut out = b"DfuSe\x01".to_vec();
    out.extend_from_slice(&((11 + 274 + tgt.len()) as u32).to_le_bytes());
    out.push(1);
    out.extend_from_slice(b"Target\x00");
    out.extend_from_slice(&1u32.to_le_bytes());
    let mut name = [0u8; 255];
    name[..3].copy_from_slice(b"ST.");
    out.extend_from_slice(&name);
    out.extend_from_slice(&(tgt.len() as u32).to_le_bytes());
    out.extend_from_slice(&(elements.len() as u32).to_le_bytes());
    out.extend_from_slice(&tgt);
    out.extend_from_slice(&[
        0, 0, 0x11, 0xdf, 0x83, 0x04, 0x1a, 0x01, b'U', b'F', b'D', 16,
    ]);
    refresh_crc(&mut out, false);
    out
}

/// Append (or overwrite) the suffix CRC so a structural corruption is what the
/// parser sees, not a CRC mismatch.
fn refresh_crc(out: &mut Vec<u8>, overwrite: bool) {
    if overwrite {
        out.truncate(out.len() - 4);
    }
    let crc = !crc32(out);
    out.extend_from_slice(&crc.to_le_bytes());
}

fn refused(raw: &[u8]) -> Mk4ImageError {
    Mk4Firmware::from_artifact(raw).expect_err("must be refused")
}

fn dfu_refused(raw: &[u8]) -> DfuError {
    match refused(raw) {
        Mk4ImageError::Container(e) => e,
        other => panic!("expected a container refusal, got {other:?}"),
    }
}

#[test]
fn published_key0_scalar_is_the_key_pubkey0_names() {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&KEY0_SECRET).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize_uncompressed();
    assert_eq!(pk[1..], PUBKEY0);
}

#[test]
fn a_key0_image_loads_raw_and_dfu_identically_and_needs_no_registry() {
    let img = ok_image();
    let raw = Mk4Firmware::from_artifact(&img).unwrap();
    let dfu = Mk4Firmware::from_artifact(&dfuse(&[(MK4_IMAGE_BASE, &img)])).unwrap();
    assert_eq!(raw.container(), Mk4Container::Raw);
    assert_eq!(dfu.container(), Mk4Container::DfuSe);
    assert_eq!(raw.as_bytes(), &img[..]);
    assert_eq!(dfu.as_bytes(), &img[..]);
    assert_eq!(raw.size(), OK_LEN);
    assert_eq!(raw.num_chunks(), 65);
    assert_eq!(raw.version(), "6.0.1t");
    // The two signed ranges, single hash — not the contiguous ESP32 prefix and
    // not the bootloader's double hash.
    let mut h = Sha256::new();
    h.update(&img[..0x3fc0]);
    h.update(&img[0x4000..]);
    let two_range: [u8; 32] = h.finalize().into();
    assert_eq!(raw.digest().0, two_range);
    assert_eq!(dfu.digest(), raw.digest());
    assert_ne!(raw.digest().0, <[u8; 32]>::from(Sha256::digest(&img)));
    assert_ne!(raw.digest().0, <[u8; 32]>::from(Sha256::digest(two_range)));
    // Unregistered and loaded anyway: the registry is not permission.
    assert_eq!(registered_mk4_revision(&raw.digest()), None);
}

#[test]
fn every_image_rule_refuses_on_its_own() {
    let n = OK_LEN as usize;
    // hw_compat 0 is "no constraint" (shared/utils.py:401), not "no product".
    assert!(Mk4Firmware::from_artifact(&synth(n, OK_LEN, 0)).is_ok());
    for hw in [0x20u32, 0x07] {
        assert_eq!(
            refused(&synth(n, OK_LEN, hw)),
            Mk4ImageError::WrongFamily(hw)
        );
    }
    let mut bad_magic = ok_image();
    put(&mut bad_magic, HDR, 0xdead_beef);
    assert_eq!(refused(&bad_magic), Mk4ImageError::Magic(0xdead_beef));
    assert_eq!(refused(&ok_image()[..4096]), Mk4ImageError::Unreadable);

    assert_eq!(
        refused(&synth(n, 4096, 0x28)),
        Mk4ImageError::TooSmall(4096)
    );
    assert_eq!(
        refused(&synth(n, u32::MAX, 0x28)),
        Mk4ImageError::TooLarge(u32::MAX)
    );
    let window = MK4_LEN_MAX + 4096;
    assert_eq!(
        refused(&synth(n, window, 0x28)),
        Mk4ImageError::TooLarge(window)
    );
    // Truncation: the file ends before the header's length.
    let img = ok_image();
    assert_eq!(
        refused(&img[..n - 4096]),
        Mk4ImageError::Truncated {
            header: OK_LEN,
            file: n - 4096
        }
    );
    // Bytes past firmware_length would be streamed but never signed.
    let mut long = ok_image();
    long.extend_from_slice(&[0xff; 4096]);
    assert_eq!(
        refused(&long),
        Mk4ImageError::LengthMismatch {
            header: OK_LEN,
            file: n + 4096
        }
    );
    // 512-aligned is enough to STAGE, not to install: validly signed, refused.
    let short_tail = 64 * 4096 + 512;
    assert_eq!(
        refused(&synth(short_tail, short_tail as u32, 0x28)),
        Mk4ImageError::Alignment(short_tail as u32)
    );

    let mut key5 = ok_image();
    put(&mut key5, HDR + 20, 5);
    sign(&mut key5);
    assert_eq!(refused(&key5), Mk4ImageError::UnsupportedKey(5));
    // One body bit after signing.
    let mut body = ok_image();
    body[n - 1] ^= 1;
    assert_eq!(refused(&body), Mk4ImageError::BadSignature);
    // One signature bit.
    let mut sig = ok_image();
    sig[HDR + 100] ^= 1;
    assert_eq!(refused(&sig), Mk4ImageError::BadSignature);
    // The header is signed too (everything but r||s).
    let mut hdr = ok_image();
    hdr[HDR + 28] ^= 1;
    assert_eq!(refused(&hdr), Mk4ImageError::BadSignature);

    for (at, byte, rule) in [
        (HDR + 12, 0xff, "R2"),
        (HDR + 12, 0x00, "R3"),
        (HDR + 4, 0x40, "R4"),
        (HDR + 12, b'2', "R10"),
    ] {
        let mut v = ok_image();
        v[at] = byte;
        sign(&mut v);
        match refused(&v) {
            Mk4ImageError::Header(r) => assert!(r.starts_with(rule), "{r} for {rule}"),
            other => panic!("{rule}: {other:?}"),
        }
    }
    let mut unpadded = ok_image();
    unpadded[HDR + 12..HDR + 20].copy_from_slice(b"6.0.1t\0x");
    sign(&mut unpadded);
    assert!(matches!(refused(&unpadded), Mk4ImageError::Header(r) if r.starts_with("R11")));
}

#[test]
fn families_do_not_cross() {
    // ESP32 image offered as Mk4: named as the wrong model, not "bad magic".
    let esp32 = include_bytes!("v0.0.1-firmware-signed.bin");
    assert_eq!(refused(esp32), Mk4ImageError::Esp32Image);
    // Mk4 image offered to the unchanged ESP32 validator.
    let mk4: &'static [u8] = Box::leak(ok_image().into_boxed_slice());
    assert!(matches!(
        FirmwareBin::new(mk4).validate(),
        Err(FirmwareValidationError::InvalidFormat(_))
    ));
}

#[test]
fn every_malformed_container_is_refused() {
    let img = ok_image();
    let good = dfuse(&[(MK4_IMAGE_BASE, &img)]);
    assert!(Mk4Firmware::from_artifact(&good).is_ok());

    assert!(matches!(dfu_refused(&good[..200]), DfuError::TooShort(200)));

    let mut crc = good.clone();
    crc[4000] ^= 1;
    assert!(matches!(dfu_refused(&crc), DfuError::Crc { .. }));

    let edit = |at: usize, v: &[u8]| {
        let mut d = good.clone();
        d[at..at + v.len()].copy_from_slice(v);
        refresh_crc(&mut d, true);
        dfu_refused(&d)
    };
    assert_eq!(edit(5, &[2]), DfuError::Version(2));
    assert!(matches!(
        edit(6, &1u32.to_le_bytes()),
        DfuError::ImageSize { declared: 1, .. }
    ));
    assert_eq!(edit(10, &[2]), DfuError::Targets(2));
    assert_eq!(edit(11, b"Tarjet"), DfuError::TargetSignature);
    assert!(matches!(
        edit(277, &1u32.to_le_bytes()),
        DfuError::TargetSize { declared: 1, .. }
    ));
    assert_eq!(
        edit(281, &2u32.to_le_bytes()),
        DfuError::ElementTruncated { index: 1 }
    );
    assert_eq!(
        edit(289, &u32::MAX.to_le_bytes()),
        DfuError::ElementTruncated { index: 0 }
    );
    assert_eq!(edit(good.len() - 5, &[15]), DfuError::Suffix);
    assert_eq!(edit(good.len() - 10, &[0x1b]), DfuError::Suffix);

    // Element list shapes.
    let small = [0u8; 64];
    let shape = |els: &[(u32, &[u8])]| dfu_refused(&dfuse(els));
    assert!(matches!(
        shape(&[(0x0801_0000, &img)]),
        DfuError::OutOfTarget {
            address: 0x0801_0000,
            ..
        }
    ));
    let past = MK4_IMAGE_BASE + MK4_LEN_MAX - 32;
    assert!(
        matches!(shape(&[(MK4_IMAGE_BASE, &img), (past, &small)]), DfuError::OutOfTarget { address, .. } if address == past)
    );
    assert_eq!(
        shape(&[(MK4_IMAGE_BASE, &img), (MK4_IMAGE_BASE + 4096, &small)]),
        DfuError::Overlap {
            first: MK4_IMAGE_BASE,
            second: MK4_IMAGE_BASE + 4096
        }
    );
    assert_eq!(
        shape(&[(MK4_IMAGE_BASE, &img), (MK4_IMAGE_BASE, &img)]),
        DfuError::Overlap {
            first: MK4_IMAGE_BASE,
            second: MK4_IMAGE_BASE
        }
    );
    let after = MK4_IMAGE_BASE + OK_LEN;
    assert_eq!(
        shape(&[(MK4_IMAGE_BASE, &img), (after, &small)]),
        DfuError::Ambiguous(vec![MK4_IMAGE_BASE, after])
    );
    assert_eq!(shape(&[(after, &small)]), DfuError::Ambiguous(vec![after]));
    assert_eq!(shape(&[]), DfuError::Ambiguous(vec![]));

    // Bytes inside the target that no element claims.
    let mut trailing = dfuse(&[(MK4_IMAGE_BASE, &img)]);
    trailing.truncate(trailing.len() - 16);
    trailing.extend_from_slice(&[0xaa; 8]);
    let tsize = u32::from_le_bytes(trailing[277..281].try_into().unwrap()) + 8;
    trailing[277..281].copy_from_slice(&tsize.to_le_bytes());
    let isize_ = (trailing.len()) as u32;
    trailing[6..10].copy_from_slice(&isize_.to_le_bytes());
    trailing.extend_from_slice(&[
        0, 0, 0x11, 0xdf, 0x83, 0x04, 0x1a, 0x01, b'U', b'F', b'D', 16,
    ]);
    refresh_crc(&mut trailing, false);
    assert_eq!(dfu_refused(&trailing), DfuError::TrailingBytes(8));

    // A well-formed container around a bad image refuses on the IMAGE rule.
    let wrong = synth(OK_LEN as usize, OK_LEN, 0x20);
    assert_eq!(
        refused(&dfuse(&[(MK4_IMAGE_BASE, &wrong)])),
        Mk4ImageError::WrongFamily(0x20)
    );
}

#[test]
fn load_reads_files_and_bounds_them_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("fw.dfu");
    std::fs::write(&p, dfuse(&[(MK4_IMAGE_BASE, &ok_image())])).unwrap();
    assert_eq!(Mk4Firmware::load(&p).unwrap().size(), OK_LEN);
    assert!(matches!(
        Mk4Firmware::load(dir.path().join("absent")),
        Err(Mk4LoadError::Io(_))
    ));
    let big = dir.path().join("big.bin");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(64 << 20)
        .unwrap();
    assert!(matches!(
        Mk4Firmware::load(&big),
        Err(Mk4LoadError::FileTooLarge(_))
    ));
    let esp = dir.path().join("esp.bin");
    std::fs::write(&esp, include_bytes!("v0.0.1-firmware-signed.bin")).unwrap();
    assert!(matches!(
        Mk4Firmware::load(&esp),
        Err(Mk4LoadError::Image(Mk4ImageError::Esp32Image))
    ));
}

// ---------------------------------------------------------------- cold-snap tier

fn coldsnap() -> PathBuf {
    PathBuf::from(
        std::env::var("COLDSNAP_REPO").expect("set COLDSNAP_REPO to the cold-snap checkout"),
    )
}

fn fixture(rel: &str) -> PathBuf {
    let p = coldsnap().join("target/software-only").join(rel);
    assert!(
        p.is_file(),
        "missing fixture {} — see evidence/06",
        p.display()
    );
    p
}

#[test]
#[ignore = "needs COLDSNAP_REPO and the task-01/05/06 fixtures"]
fn real_task01_artifacts_and_an_unregistered_local_build_load() {
    let raw = Mk4Firmware::load(fixture("package/firmware-signed.bin")).unwrap();
    let dfu = Mk4Firmware::load(fixture("package/coldsnap-6.0.0cs.dfu")).unwrap();
    assert_eq!(raw.as_bytes(), dfu.as_bytes());
    assert_eq!(raw.digest(), dfu.digest());
    assert_eq!(raw.size() % MK4_INSTALL_ALIGN, 0);
    // Recognized by the registry, which is display metadata only ...
    assert!(registered_mk4_revision(&raw.digest()).is_some());

    // ... and a local build that no registry names loads just the same.
    let local = Mk4Firmware::load(fixture("fixtures/06/local-build/firmware-signed.bin")).unwrap();
    let local_dfu =
        Mk4Firmware::load(fixture("fixtures/06/local-build/coldsnap-6.0.1lb.dfu")).unwrap();
    assert_eq!(local.as_bytes(), local_dfu.as_bytes());
    assert_eq!(local.version(), "6.0.1lb");
    assert_ne!(local.digest(), raw.digest());
    assert_eq!(registered_mk4_revision(&local.digest()), None);
}

#[test]
#[ignore = "needs COLDSNAP_REPO and the task-01/05 fixtures"]
fn real_negative_fixtures_refuse_for_their_own_reason() {
    let e = |rel: &str| match Mk4Firmware::load(fixture(rel)) {
        Err(Mk4LoadError::Image(e)) => e,
        other => panic!("{rel}: {other:?}"),
    };
    assert_eq!(e("fixtures/bad-signature.bin"), Mk4ImageError::BadSignature);
    assert_eq!(
        e("fixtures/05/misaligned-397824.bin"),
        Mk4ImageError::Alignment(397_824)
    );
    assert_eq!(
        e("fixtures/05/wrong-family-mk5-only.bin"),
        Mk4ImageError::WrongFamily(0x20)
    );
}

/// `golden/mk4-staging-vectors.txt`: the digest cold-snap's production
/// `firmware_digest` and hostcheck's M13 both pin. Read at runtime (not
/// `include_str!`) so the hermetic tier builds without a cold-snap checkout.
#[test]
#[ignore = "needs COLDSNAP_REPO"]
fn two_range_digest_matches_the_golden_vector() {
    let text = std::fs::read_to_string(coldsnap().join("golden/mk4-staging-vectors.txt")).unwrap();
    let line = text
        .lines()
        .find(|l| l.starts_with("m13-synth-262656 "))
        .expect("vector present");
    let f: Vec<&str> = line.split_whitespace().collect();
    let size: usize = f[1].parse().unwrap();
    let mut img: Vec<u8> = (0..size).map(|i| (i * 7 + i / 251) as u8).collect();
    img[16280..16284].copy_from_slice(&(size as u32).to_le_bytes());
    let hex = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let announced = two_range_digest(&img);
    assert_eq!(hex(&announced.0), f[2]);
    assert_eq!(hex(&Sha256::digest(announced.0)), f[3]);
    assert_eq!(hex(&Sha256::digest(&img)), f[4]);
}

/// The port is only as good as its agreement with the original. Run cold-snap's
/// `checkfw` (which calls `coldsnap_hal::image::check_installable` as R14) over
/// every raw image and require the same verdict.
#[test]
#[ignore = "needs COLDSNAP_REPO and a built checkfw example"]
fn verdicts_agree_with_coldsnap_checkfw() {
    let checkfw = coldsnap().join("target/aarch64-apple-darwin/debug/examples/checkfw");
    assert!(
        checkfw.is_file(),
        "build it: cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut cases: Vec<PathBuf> = [
        "package/firmware-signed.bin",
        "package/coldsnap-6.0.0cs.dfu",
        "fixtures/06/local-build/firmware-signed.bin",
        "fixtures/bad-signature.bin",
        "fixtures/05/misaligned-397824.bin",
        "fixtures/05/wrong-family-mk5-only.bin",
    ]
    .iter()
    .map(|r| fixture(r))
    .collect();
    let n = OK_LEN as usize;
    let mut body = ok_image();
    body[n - 1] ^= 1;
    let mut r4 = ok_image();
    r4[HDR + 4] = 0x40;
    sign(&mut r4);
    let short_tail = 64 * 4096 + 512;
    for (name, bytes) in [
        ("ok.bin", ok_image()),
        ("hw0.bin", synth(n, OK_LEN, 0)),
        ("mk5.bin", synth(n, OK_LEN, 0x20)),
        ("small.bin", synth(n, 4096, 0x28)),
        ("large.bin", synth(n, MK4_LEN_MAX + 4096, 0x28)),
        ("tail.bin", synth(short_tail, short_tail as u32, 0x28)),
        ("body.bin", body),
        ("r4.bin", r4),
    ] {
        let p = dir.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        cases.push(p);
    }
    let mut accepted = 0;
    for p in &cases {
        let out = std::process::Command::new(&checkfw)
            .arg(p)
            .output()
            .unwrap();
        let code = out.status.code().expect("checkfw exited, not signalled");
        assert!(
            code == 0 || code == 1,
            "checkfw {} exit {code} (self-test/usage?)",
            p.display()
        );
        let ours = Mk4Firmware::load(p);
        assert_eq!(
            code == 0,
            ours.is_ok(),
            "{}: checkfw exit {code}, ours {ours:?}",
            p.display()
        );
        accepted += usize::from(code == 0);
    }
    // Not vacuous in either direction.
    assert_eq!(
        accepted, 5,
        "ok, hw0, two task-01 artifacts, the local build"
    );
}
