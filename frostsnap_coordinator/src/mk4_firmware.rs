//! The checked cold-snap Mk4 firmware artifact: load, unwrap, validate, digest.
//!
//! Separate from the ESP32 [`crate::FirmwareBin`] / [`crate::ValidatedFirmwareBin`]
//! on purpose. The two families share nothing but the transfer chunk size: a
//! different header, a different length rule, a different signature and a
//! different digest. Neither type accepts the other family's image, and each
//! names the refusal (`Mk4ImageError::Esp32Image` here).
//!
//! # Where every rule comes from (and why it is ported, not imported)
//!
//! The rules are cold-snap's task-05 install boundary,
//! `coldsnap_hal::image::check_installable`, plus `checkfw`'s R12 key-0 signature
//! check. This crate cannot depend on `coldsnap_hal`: one cargo graph will not
//! hold cold-snap's vendored `frostsnap_comms` and this one
//! (`cold-snap/hostcheck/Cargo.toml` records cargo's refusal). So they are PORTED
//! here, one rule per `check_installable` rule in the same order, and BOUND to
//! the originals by tests rather than trusted to stay in sync:
//!
//! * `tests/mk4_firmware_artifacts.rs` runs cold-snap's own `checkfw` over every
//!   real and negative fixture and requires the same accept/refuse verdict, and
//!   checks [`two_range_digest`] against `cold-snap/golden/mk4-staging-vectors.txt`.
//! * The unit tests below verify Coinkite's released 6.3.5X signature vector
//!   (copied from `checkfw.rs` `REF_FW_CHECK`/`REF_SIG`) under [`PUBKEY0`].
//!
//! # What this is NOT
//!
//! Not authentication. Dev key 0's private half is published
//! (`coldcard-firmware/stm32/keys/README.md`); the signature is a FORMAT check
//! that the image is what the Mk4 bootloader will parse, and the digest is
//! transfer integrity. No registry, allowlist, manifest, share proof or rollback
//! rule is consulted: a local build whose digest is registered nowhere loads
//! exactly like a recognized one.

use frostsnap_comms::Sha256Digest;
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::sync::Arc;

/// `memmap::FLASH_ISR_BASE`: the only flash address an Mk4 image may load at.
pub const MK4_IMAGE_BASE: u32 = 0x0802_0000;
/// `memmap::FLASH_FS_BASE`. An image reaching it would erase the share.
const MK4_FLASH_FS_BASE: u32 = 0x0818_0000;
/// `psram::BURN_LEN_MAX` = `FLASH_FS_BASE - FLASH_ISR_BASE`.
pub const MK4_LEN_MAX: u32 = MK4_FLASH_FS_BASE - MK4_IMAGE_BASE;
/// `psram::BURN_LEN_MIN` = `memmap::FW_MIN_BODY_LEN`.
pub const MK4_LEN_MIN: u32 = 256 * 1024;
/// `memmap::FW_INSTALL_ALIGN`: the Mk4 flash erase stride (`signit.py:305`).
/// NOT the 512-byte staging alignment.
pub const MK4_INSTALL_ALIGN: u32 = 4096;
/// `memmap::FW_HEADER_OFFSET` = `FLASH_ISR_LEN (16 K) - FW_HEADER_SIZE (128)`.
const HDR_OFF: usize = 0x3f80;
const HDR_SIZE: usize = 128;
/// The 64-byte `r||s` sits at the end of the header and is punched out of the
/// signed range: `[0, SIG_START) ++ [SIG_END, len)` (`verify.c:265-273`).
const SIG_START: usize = HDR_OFF + 64;
const SIG_END: usize = HDR_OFF + HDR_SIZE;
/// `image::FW_HEADER_MAGIC` (`sigheader.h:41`).
pub const MK4_HEADER_MAGIC: u32 = 0xCC00_1234;
/// Header field offsets (`sigheader.h:26-32`).
const PUBKEY_NUM_OFF: usize = 20;
const LENGTH_OFF: usize = 24; // psram::FW_LENGTH_FIELD_OFFSET
const HW_COMPAT_OFF: usize = 32; // image::HW_COMPAT_FIELD_OFFSET
/// `image::MK_4_OK` (`sigheader.h:71`).
const MK_4_OK: u32 = 0x08;
/// `frostsnap_comms::firmware_reader` ESP32 image magic, used only to NAME the
/// wrong-family refusal.
const ESP32_MAGIC: u8 = 0xE9;

/// `approved_pubkeys[0]` (`mk4-bootloader/firmware-keys.h:10-11`), raw X||Y — the
/// published dev key. Same bytes as `checkfw.rs` `PUBKEY0`.
pub const PUBKEY0: [u8; 64] = [
    0xb4, 0xcb, 0x41, 0x26, 0xf7, 0xe1, 0x6c, 0xf3, 0x8f, 0xf2, 0xb4, 0x71, 0x1d, 0xfb, 0x23, 0x01,
    0x0d, 0x76, 0xd6, 0x66, 0xa7, 0x8a, 0xa3, 0x6c, 0x9b, 0x53, 0xf9, 0xf6, 0x7b, 0x58, 0x18, 0x05,
    0x58, 0x0b, 0x3b, 0xe9, 0x31, 0xc4, 0x9f, 0xb8, 0x44, 0x04, 0x3c, 0x11, 0x96, 0x08, 0x0f, 0x47,
    0x81, 0x25, 0xed, 0x37, 0x7a, 0x23, 0x9e, 0x4a, 0xaf, 0xb7, 0x18, 0x38, 0xba, 0x38, 0x04, 0xda,
];

/// Why a DfuSe container was refused. Every length in the file is untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DfuError {
    /// Shorter than prefix + one target prefix + suffix.
    TooShort(usize),
    /// DfuSe prefix version is not 1.
    Version(u8),
    /// `DFUImageSize` is not the file length minus the 16-byte suffix.
    ImageSize { declared: u32, actual: usize },
    /// Exactly one target is supported (`sdcard.c:156-205` walks one).
    Targets(u8),
    /// Target prefix does not start with `"Target"`.
    TargetSignature,
    /// Target size does not equal the bytes between its prefix and the suffix.
    TargetSize { declared: u32, actual: usize },
    /// An element header or body runs past the target.
    ElementTruncated { index: u32 },
    /// An element lies (partly) outside `[MK4_IMAGE_BASE, +MK4_LEN_MAX)`.
    OutOfTarget { address: u32, size: u32 },
    /// Two elements cover the same flash.
    Overlap { first: u32, second: u32 },
    /// Elements end before the target does: bytes nobody accounts for.
    TrailingBytes(usize),
    /// Not exactly one element, at [`MK4_IMAGE_BASE`]. Carries every element
    /// address, so "which one did you mean" is answerable from the message.
    Ambiguous(Vec<u32>),
    /// Suffix `bLength`/`"UFD"`/`bcdDFU` wrong.
    Suffix,
    /// Suffix CRC does not match the file.
    Crc { stored: u32, computed: u32 },
}

/// Why a Mk4 image was refused before any transfer. Ordered like
/// `check_installable` — format before length — then the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mk4ImageError {
    Container(DfuError),
    /// This is an ESP32 image (`0xE9` magic), i.e. the wrong device family.
    Esp32Image,
    /// Too short to contain the 128-byte header.
    Unreadable,
    Magic(u32),
    /// `hw_compat` does not admit Mk4 (`image::family_ok`).
    WrongFamily(u32),
    /// `firmware_length` is below [`MK4_LEN_MIN`].
    TooSmall(u32),
    /// `firmware_length` would reach `FLASH_FS` (`psram::StageError::TooLarge`).
    TooLarge(u32),
    /// `firmware_length` is longer than the file.
    Truncated {
        header: u32,
        file: usize,
    },
    /// The file carries bytes past `firmware_length` (`check_burn_len`
    /// `LengthMismatch`, `checkfw` R9).
    LengthMismatch {
        header: u32,
        file: usize,
    },
    /// Not a multiple of [`MK4_INSTALL_ALIGN`].
    Alignment(u32),
    /// A header field the bootloader or installer refuses (`checkfw` R2-R4,
    /// R10, R11). Carries the rule, e.g. `"R4 timestamp[0] < 0x40"`.
    Header(&'static str),
    /// Signed with a key other than the published dev key 0. Keys 1-5 are
    /// Coinkite's and are not embedded, so this is unverifiable here, not "bad".
    UnsupportedKey(u32),
    /// The key-0 signature over sha256(two-range digest) does not verify.
    BadSignature,
}

impl std::fmt::Display for Mk4ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Mk4ImageError::*;
        match self {
            Container(e) => write!(f, "malformed DfuSe container: {e:?}"),
            Esp32Image => write!(
                f,
                "wrong model: this is an ESP32 Frostsnap image, not a Mk4 image"
            ),
            Unreadable => write!(f, "too short to contain a Mk4 firmware header"),
            Magic(m) => write!(
                f,
                "not a Mk4 image: header magic {m:#010x}, expected {MK4_HEADER_MAGIC:#010x}"
            ),
            WrongFamily(hw) => write!(
                f,
                "wrong model: hw_compat {hw:#x} does not admit Mk4 ({MK_4_OK:#x})"
            ),
            TooSmall(n) => write!(
                f,
                "firmware_length {n} is below the {MK4_LEN_MIN}-byte floor"
            ),
            TooLarge(n) => write!(
                f,
                "firmware_length {n} exceeds the {MK4_LEN_MAX}-byte burn window"
            ),
            Truncated { header, file } => {
                write!(f, "truncated: header says {header} bytes, file has {file}")
            }
            LengthMismatch { header, file } => write!(
                f,
                "length mismatch: header says {header} bytes, file has {file}"
            ),
            Alignment(n) => write!(
                f,
                "firmware_length {n} is not a multiple of {MK4_INSTALL_ALIGN}"
            ),
            Header(rule) => write!(f, "header refused by rule {rule}"),
            UnsupportedKey(k) => write!(
                f,
                "signed with key {k}; only the published dev key 0 is checkable"
            ),
            BadSignature => write!(
                f,
                "dev-key-0 signature does not verify over the signed ranges"
            ),
        }
    }
}
impl std::error::Error for Mk4ImageError {}

#[derive(Debug)]
pub enum Mk4LoadError {
    Io(std::io::Error),
    /// The file is larger than any valid container could be; refused unread.
    FileTooLarge(u64),
    Image(Mk4ImageError),
}

impl std::fmt::Display for Mk4LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mk4LoadError::Io(e) => write!(f, "cannot read Mk4 artifact: {e}"),
            Mk4LoadError::FileTooLarge(n) => {
                write!(f, "{n}-byte file is larger than any Mk4 artifact")
            }
            Mk4LoadError::Image(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for Mk4LoadError {}

impl From<Mk4ImageError> for Mk4LoadError {
    fn from(e: Mk4ImageError) -> Self {
        Mk4LoadError::Image(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mk4Container {
    Raw,
    DfuSe,
}

/// A Mk4 image that passed every pre-transfer check. The only way to obtain one
/// is [`Mk4Firmware::from_artifact`] / [`Mk4Firmware::load`], so holding one means
/// the checks ran.
#[derive(Clone)]
pub struct Mk4Firmware {
    image: Arc<[u8]>,
    digest: Sha256Digest,
    container: Mk4Container,
    hw_compat: u32,
    version: String,
}

impl std::fmt::Debug for Mk4Firmware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mk4Firmware")
            .field("size", &self.image.len())
            .field("digest", &self.digest)
            .field("container", &self.container)
            .field("version", &self.version)
            .finish()
    }
}

impl Mk4Firmware {
    /// Load a raw signed image or a DfuSe file from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Mk4LoadError> {
        let path = path.as_ref();
        // A container is the image plus < 4 KiB of framing; refuse anything
        // bigger before reading it.
        let len = std::fs::metadata(path).map_err(Mk4LoadError::Io)?.len();
        if len > u64::from(MK4_LEN_MAX) + 4096 {
            return Err(Mk4LoadError::FileTooLarge(len));
        }
        let raw = std::fs::read(path).map_err(Mk4LoadError::Io)?;
        Ok(Self::from_artifact(&raw)?)
    }

    /// Unwrap (if DfuSe) and validate an artifact held in memory.
    pub fn from_artifact(raw: &[u8]) -> Result<Self, Mk4ImageError> {
        let (image, container) = if raw.starts_with(b"DfuSe") {
            (
                extract_dfuse(raw).map_err(Mk4ImageError::Container)?,
                Mk4Container::DfuSe,
            )
        } else {
            (raw, Mk4Container::Raw)
        };
        let checked = check_mk4_image(image)?;
        Ok(Self {
            image: image.into(),
            digest: checked.digest,
            container,
            hw_compat: checked.hw_compat,
            version: checked.version,
        })
    }

    /// The bytes to stream: exactly the image at [`MK4_IMAGE_BASE`].
    pub fn as_bytes(&self) -> &[u8] {
        &self.image
    }

    /// The announced size, which equals the header's `firmware_length`.
    pub fn size(&self) -> u32 {
        self.image.len() as u32
    }

    /// The Mk4 transfer digest: ONE sha256 over the two signed ranges. Not the
    /// bootloader's double hash, not the ESP32 contiguous-prefix digest.
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn num_chunks(&self) -> u32 {
        self.size()
            .div_ceil(frostsnap_comms::FIRMWARE_UPGRADE_CHUNK_LEN)
    }

    pub fn container(&self) -> Mk4Container {
        self.container
    }

    pub fn hw_compat(&self) -> u32 {
        self.hw_compat
    }

    /// Header `version_string`, NUL-trimmed, non-printables as `?`. Display only.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// What [`check_mk4_image`] measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedMk4Image {
    pub length: u32,
    pub digest: Sha256Digest,
    pub hw_compat: u32,
    pub version: String,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// `sha256(img[..0x3fc0] ++ img[0x4000..])` — cold-snap's announced/staged digest
/// (`coldsnap_firmware::firmware_digest`). Caller guarantees `img.len() >= 0x4000`.
pub fn two_range_digest(img: &[u8]) -> Sha256Digest {
    let mut h = Sha256::new();
    h.update(&img[..SIG_START]);
    h.update(&img[SIG_END..]);
    Sha256Digest(h.finalize().into())
}

/// Verify a compact `r||s` under [`PUBKEY0`] over `fw_check`, normalizing S first
/// (uECC accepts high-S and `signit.py` does not canonicalize; `checkfw` R12).
fn verify_key0(fw_check: [u8; 32], sig: &[u8]) -> bool {
    use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
    let mut sec1 = [4u8; 65];
    sec1[1..].copy_from_slice(&PUBKEY0);
    let (Ok(pk), Ok(mut sig)) = (PublicKey::from_slice(&sec1), Signature::from_compact(sig)) else {
        return false;
    };
    sig.normalize_s();
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(fw_check), &sig, &pk)
        .is_ok()
}

/// Every pre-transfer rule, over the image bytes alone. The port of
/// `check_installable(image, image.len())` followed by `checkfw` R12.
pub fn check_mk4_image(image: &[u8]) -> Result<CheckedMk4Image, Mk4ImageError> {
    let Some(h) = image.get(HDR_OFF..SIG_END) else {
        if image.first() == Some(&ESP32_MAGIC) {
            return Err(Mk4ImageError::Esp32Image);
        }
        return Err(Mk4ImageError::Unreadable);
    };
    let magic = u32_at(h, 0);
    if magic != MK4_HEADER_MAGIC {
        return Err(if image[0] == ESP32_MAGIC {
            Mk4ImageError::Esp32Image
        } else {
            Mk4ImageError::Magic(magic)
        });
    }
    let hw_compat = u32_at(h, HW_COMPAT_OFF);
    if hw_compat != 0 && hw_compat & MK_4_OK == 0 {
        return Err(Mk4ImageError::WrongFamily(hw_compat));
    }
    let length = u32_at(h, LENGTH_OFF);
    if length < MK4_LEN_MIN {
        return Err(Mk4ImageError::TooSmall(length));
    }
    if MK4_IMAGE_BASE
        .checked_add(length)
        .is_none_or(|end| end > MK4_FLASH_FS_BASE)
    {
        return Err(Mk4ImageError::TooLarge(length));
    }
    if length as usize > image.len() {
        return Err(Mk4ImageError::Truncated {
            header: length,
            file: image.len(),
        });
    }
    if length as usize != image.len() {
        return Err(Mk4ImageError::LengthMismatch {
            header: length,
            file: image.len(),
        });
    }
    if length % MK4_INSTALL_ALIGN != 0 {
        return Err(Mk4ImageError::Alignment(length));
    }
    let (ts, ver) = (&h[4..12], &h[12..20]);
    let header_rules: [(bool, &'static str); 5] = [
        (
            ver[0] != 0xff,
            "R2 version_string[0] != 0xff (verify.c:319)",
        ),
        (
            ver[0] != 0x00,
            "R3 version_string[0] != 0x00 (verify.c:213)",
        ),
        (ts[0] < 0x40, "R4 timestamp[0] < 0x40 (verify.c:214)"),
        (
            ver[1] != b'.' || (ver[0] as char).to_digit(10).unwrap_or(0) >= 3,
            "R10 version major >= 3 (verify.c:171-172 downgrade gate)",
        ),
        (
            ver.iter()
                .position(|&b| b == 0)
                .is_some_and(|n| ver[n..].iter().all(|&b| b == 0)),
            "R11 version_string NUL-padded (signit.py:263)",
        ),
    ];
    if let Some((_, rule)) = header_rules.iter().find(|(ok, _)| !ok) {
        return Err(Mk4ImageError::Header(rule));
    }
    let pubkey_num = u32_at(h, PUBKEY_NUM_OFF);
    if pubkey_num != 0 {
        return Err(Mk4ImageError::UnsupportedKey(pubkey_num));
    }
    let digest = two_range_digest(image);
    if !verify_key0(Sha256::digest(digest.0).into(), &h[64..128]) {
        return Err(Mk4ImageError::BadSignature);
    }
    let version = ver
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| if b.is_ascii_graphic() { b as char } else { '?' })
        .collect();
    Ok(CheckedMk4Image {
        length,
        digest,
        hw_compat,
        version,
    })
}

/// DfuSe v1 (ST UM0391, as written by `micropython/tools/dfu.py`): 11-byte
/// prefix, one 274-byte target prefix, elements `(addr u32, size u32, data)`,
/// 16-byte suffix with a CRC. Returns the one element at [`MK4_IMAGE_BASE`].
///
/// Stricter than `checkfw`'s `locate_image`, which takes the FIRST element at
/// the base and ignores the rest: here anything the transfer would silently
/// drop — a second element, an overlap, trailing bytes — is a refusal.
pub fn extract_dfuse(raw: &[u8]) -> Result<&[u8], DfuError> {
    const PREFIX: usize = 11;
    const TARGET_PREFIX: usize = 274;
    const SUFFIX: usize = 16;
    const ELEMS: usize = PREFIX + TARGET_PREFIX;
    if raw.len() < ELEMS + SUFFIX || !raw.starts_with(b"DfuSe") {
        return Err(DfuError::TooShort(raw.len()));
    }
    let body_end = raw.len() - SUFFIX;

    let (suffix, crc_field) = raw[body_end..].split_at(12);
    if suffix[6..8] != [0x1a, 0x01] || &suffix[8..11] != b"UFD" || suffix[11] != 16 {
        return Err(DfuError::Suffix);
    }
    let stored = u32::from_le_bytes(crc_field.try_into().expect("4 bytes"));
    let computed = !crc32(&raw[..raw.len() - 4]);
    if stored != computed {
        return Err(DfuError::Crc { stored, computed });
    }

    if raw[5] != 1 {
        return Err(DfuError::Version(raw[5]));
    }
    let declared = u32_at(raw, 6);
    if declared as usize != body_end {
        return Err(DfuError::ImageSize {
            declared,
            actual: body_end,
        });
    }
    if raw[10] != 1 {
        return Err(DfuError::Targets(raw[10]));
    }
    if &raw[PREFIX..PREFIX + 6] != b"Target" {
        return Err(DfuError::TargetSignature);
    }
    let target_size = u32_at(raw, ELEMS - 8);
    if target_size as usize != body_end - ELEMS {
        return Err(DfuError::TargetSize {
            declared: target_size,
            actual: body_end - ELEMS,
        });
    }
    let n_elements = u32_at(raw, ELEMS - 4);

    let window_end = u64::from(MK4_IMAGE_BASE) + u64::from(MK4_LEN_MAX);
    let mut at = ELEMS;
    let mut spans: Vec<(u32, u64, usize)> = Vec::new(); // (addr, end, data offset)
    for index in 0..n_elements {
        let hdr = raw.get(at..at + 8).filter(|_| at + 8 <= body_end);
        let Some(hdr) = hdr else {
            return Err(DfuError::ElementTruncated { index });
        };
        let (address, size) = (u32_at(hdr, 0), u32_at(hdr, 4));
        let data = at + 8;
        let Some(next) = data.checked_add(size as usize).filter(|&e| e <= body_end) else {
            return Err(DfuError::ElementTruncated { index });
        };
        let end = u64::from(address) + u64::from(size);
        if address < MK4_IMAGE_BASE || end > window_end {
            return Err(DfuError::OutOfTarget { address, size });
        }
        if let Some(&(first, _, _)) = spans
            .iter()
            .find(|&&(a, e, _)| u64::from(address) < e && u64::from(a) < end)
        {
            return Err(DfuError::Overlap {
                first,
                second: address,
            });
        }
        spans.push((address, end, data));
        at = next;
    }
    if at != body_end {
        return Err(DfuError::TrailingBytes(body_end - at));
    }
    match spans.as_slice() {
        [(addr, end, data)] if *addr == MK4_IMAGE_BASE => {
            Ok(&raw[*data..*data + (*end - u64::from(*addr)) as usize])
        }
        _ => Err(DfuError::Ambiguous(spans.iter().map(|s| s.0).collect())),
    }
}

/// zlib CRC-32 (reflected, poly 0xEDB88320). `dfu.py` stores its complement.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `checkfw.rs` `REF_FW_CHECK` / `REF_SIG` / `REF_SIG_HIGH_S`: Coinkite's
    /// released 6.3.5X Mk4 image, signed with key 0. Binds [`PUBKEY0`] and the
    /// normalize-S path to a signature this code did not produce.
    const REF_FW_CHECK: [u8; 32] = [
        0x87, 0xd1, 0x6b, 0xf4, 0xf5, 0x74, 0x40, 0x3b, 0x69, 0xaf, 0xba, 0x11, 0xdd, 0x4a, 0xfe,
        0x2b, 0x18, 0x37, 0xd9, 0xe2, 0x8c, 0x56, 0x41, 0xe8, 0xe8, 0x41, 0x4f, 0x94, 0x28, 0x25,
        0x1a, 0x2d,
    ];
    const REF_SIG: [u8; 64] = [
        0x34, 0x48, 0xef, 0x0f, 0xc9, 0x03, 0xc8, 0x76, 0x91, 0xcb, 0xf1, 0x59, 0x31, 0x01, 0x19,
        0x50, 0x64, 0xf3, 0xff, 0x07, 0xe2, 0xe9, 0xb8, 0x6f, 0xe0, 0x84, 0xbc, 0xef, 0x8f, 0x20,
        0x5d, 0xfe, 0x5f, 0xa3, 0xf5, 0xca, 0x6a, 0x06, 0xaf, 0x6b, 0x73, 0x43, 0xb5, 0xda, 0xfd,
        0x4d, 0x4f, 0xe4, 0xfa, 0x52, 0x67, 0xf0, 0xdb, 0x88, 0xda, 0xdc, 0xad, 0x84, 0x54, 0x85,
        0xfd, 0x65, 0xe8, 0xbd,
    ];
    const REF_SIG_HIGH_S: [u8; 32] = [
        0xa0, 0x5c, 0x0a, 0x35, 0x95, 0xf9, 0x50, 0x94, 0x8c, 0xbc, 0x4a, 0x25, 0x02, 0xb2, 0xb0,
        0x19, 0xc0, 0x5c, 0x74, 0xf5, 0xd3, 0xbf, 0xc5, 0x5f, 0x12, 0x4e, 0x0a, 0x06, 0xd2, 0xd0,
        0x58, 0x84,
    ];

    #[test]
    fn released_key0_vector_verifies_and_high_s_is_normalized() {
        assert!(verify_key0(REF_FW_CHECK, &REF_SIG));
        let mut flipped = REF_FW_CHECK;
        flipped[0] ^= 1;
        assert!(!verify_key0(flipped, &REF_SIG));
        let mut high = REF_SIG;
        high[32..].copy_from_slice(&REF_SIG_HIGH_S);
        assert!(
            verify_key0(REF_FW_CHECK, &high),
            "high-S must verify after normalize_s"
        );
    }

    #[test]
    fn crc32_is_zlibs() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
