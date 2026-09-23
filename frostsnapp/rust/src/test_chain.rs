//! DEV/TEST-ONLY chain fixtures, plus an INDEPENDENT Taproot key-spend check.
//!
//! Two unrelated jobs that share one reason to exist: the cold-snap app rig
//! (`cold-snap/tools/app-rig.py`) gives the real app real devices, but it cannot give it
//! coins, and a signature the app itself declares finished is not evidence that it signs.
//!
//! **Fixtures, not a chain source.** [`inject_funding`] hands the wallet a funding
//! transaction the way a completed Electrum sync would — through the shipping
//! `CoordSuperWallet::apply_update` — and nothing else. There is no Electrum server on this
//! machine and `bitcoin-node` speaks JSON-RPC, not the Electrum protocol, so a rig run has
//! no chain to sync against; this is the substitute, and it is deliberately the *only*
//! injection point, reusing the same `Update` shape `chain_sync` delivers. Everything
//! downstream — coin selection, `commit_send`, the change index, the signing session — is
//! the app's own code on the app's own data.
//!
//! **The verifier is independent of the signer, and that is the whole point.**
//! [`verify_taproot_key_spends`] starts from the *finalised transaction's bytes* and the
//! prevouts the wallet actually holds, recomputes each BIP-341 sighash with
//! `bitcoin::sighash::SighashCache`, and checks the witness signature with
//! `secp256k1::verify_schnorr` (libsecp256k1). The signing path never runs through here: the
//! coordinator's sighashes come from `frostsnap_core::bitcoin_transaction::TransactionTemplate::iter_sighash`
//! over the *template*, and its signatures come from `schnorr_fun`'s FROST. So a template
//! that disagrees with the transaction it produced, a signature witnessed onto the wrong
//! input, or a share that is simply wrong all fail here. What this does NOT re-derive is
//! libsecp256k1 itself, which both sides bottom out in.
//!
//! Neither function is wired into any production path. `api::SuperWallet::test_inject_funding`
//! and `api::SuperWallet::verify_taproot_signatures` are the only callers, and they are
//! reachable only from a test that already chose the pty transport
//! (`api::Api::load_test_pty_serial`).

use anyhow::{anyhow, bail, Context as _, Result};
use bitcoin::{
    consensus::encode::deserialize_hex,
    hashes::{sha256, Hash as _},
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use frostsnap_coordinator::{
    bdk_chain::{spk_client::FullScanResponse, BlockId, ConfirmationBlockTime, TxUpdate},
    bitcoin::wallet::CoordSuperWallet,
};
use frostsnap_core::MasterAppkey;
use std::sync::Arc;
use tracing::{event, Level};

/// Stamped on every fixture block so a run is byte-identical to the last one. A real
/// `confirmation_time` comes off a block header; nothing here has one.
const FIXTURE_BLOCK_TIME: u64 = 1_700_000_000;

/// Domain-separates the synthetic funding transaction's fake input, so its txid cannot
/// collide with a real transaction's by accident and reads as a fixture in a log.
const SYNTHETIC_PREVOUT_TAG: &[u8] = b"cold-snap app rig funding fixture v1";

/// Obviously-not-a-block-hash, and unique per height so `CheckPoint::insert` sees a distinct
/// block at each one. Never leaves the app's own local chain: no fixture block is ever sent
/// anywhere, and regtest acceptance goes through raw transactions, not headers.
fn fixture_block_hash(height: u32) -> BlockHash {
    let mut bytes = [0xf1u8; 32];
    bytes[..4].copy_from_slice(&height.to_le_bytes());
    BlockHash::from_byte_array(bytes)
}

/// A 1-in-1-out transaction paying `spk`, whose txid is a pure function of `(spk, value)` so
/// two rig runs produce the same fixture.
///
/// ITS INPUT DOES NOT EXIST on any network. That is fine for a wallet fixture — bdk is being
/// told "this transaction happened", which is exactly what a sync tells it — and it is why
/// regtest acceptance of a spend of this coin is NOT available: Core would reject the parent.
/// Pass a real funding transaction to [`inject_funding`] for that.
fn synthetic_funding_tx(spk: ScriptBuf, value: u64) -> Transaction {
    let mut preimage = SYNTHETIC_PREVOUT_TAG.to_vec();
    preimage.extend_from_slice(spk.as_bytes());
    preimage.extend_from_slice(&value.to_le_bytes());
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(sha256::Hash::hash(&preimage).to_byte_array()),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    }
}

/// Give `master_appkey` a confirmed coin, and return the funding transaction's txid.
///
/// `funding_tx_hex`:
/// * `None` — synthesize a deterministic payment of `value` sats to this wallet's next
///   external address. Spendable by the app, not by any network.
/// * `Some(raw hex)` — take a REAL transaction, e.g. one `bitcoin-cli -regtest sendtoaddress`
///   just made (`cold-snap/tools/regtest.py fund`). `value` is ignored; the amount is
///   whatever the transaction pays. Use this when the spend has to be handed back to
///   `testmempoolaccept`, because then the prevout Core needs really exists.
///
/// Which output is ours is decided by the WALLET's own derivation (`spk_path`), never by the
/// caller, so a funding transaction paying somewhere else is an error rather than a coin the
/// wallet cannot spend.
pub fn inject_funding(
    wallet: &mut CoordSuperWallet,
    master_appkey: MasterAppkey,
    value: u64,
    funding_tx_hex: Option<String>,
) -> Result<Txid> {
    // Also initialises the key's descriptors and indexer as a side effect
    // (`lazily_initialize_key`), which `spk_path` below needs, and names the index a
    // synthetic payment should land on.
    let next_address = wallet.next_address(master_appkey);

    let tx = match &funding_tx_hex {
        Some(hex) => deserialize_hex::<Transaction>(hex.trim())
            .context("funding_tx_hex is not a consensus-encoded transaction")?,
        None => synthetic_funding_tx(next_address.address.script_pubkey(), value),
    };
    let txid = tx.compute_txid();

    let (vout, path) = tx
        .output
        .iter()
        .enumerate()
        .find_map(|(vout, txout)| {
            wallet
                .spk_path(master_appkey, txout.script_pubkey.clone())
                .map(|path| (vout as u32, path))
        })
        .with_context(|| {
            format!("funding transaction {txid} pays no script this wallet derives")
        })?;

    // One past the tip, so repeated injections stack instead of replacing each other.
    let height = wallet.chain_tip().height() + 1;
    let block = BlockId {
        height,
        hash: fixture_block_hash(height),
    };
    // `TxUpdate` is `#[non_exhaustive]`, so it is built the way `chain_sync` builds one.
    let mut tx_update = TxUpdate::default();
    tx_update.txs = vec![Arc::new(tx.clone())];
    tx_update.anchors = [(
        ConfirmationBlockTime {
            block_id: block,
            confirmation_time: FIXTURE_BLOCK_TIME,
        },
        txid,
    )]
    .into();
    let update = FullScanResponse {
        tx_update,
        // What a server reporting activity on that script would have said, which is what
        // moves the keychain's reveal frontier.
        last_active_indices: [((master_appkey, path.account_keychain), path.index.to_u32())].into(),
        // `insert` on the current tip, so the update connects to the chain already stored.
        chain_update: Some(wallet.chain_tip().insert(block)),
    };
    wallet
        .apply_update(update)
        .context("applying the fixture chain update")?;

    let outpoint = OutPoint { txid, vout };
    let txout = wallet.get_txout(outpoint).with_context(|| {
        format!("the wallet did not take fixture coin {outpoint}; the update was dropped")
    })?;
    event!(
        Level::WARN,
        outpoint = outpoint.to_string(),
        value = txout.value.to_sat(),
        height,
        synthetic = funding_tx_hex.is_none(),
        "TEST CHAIN FIXTURE injected: this coin came from no chain source"
    );
    Ok(txid)
}

/// Check every input of `tx` as a BIP-341 key-path spend, against sighashes recomputed here
/// from `tx` and `prevouts`. Returns the number of inputs verified.
///
/// `prevouts` must be in input order and complete: a Taproot sighash commits to EVERY
/// prevout's amount and script, so one missing entry makes the hash — and therefore the
/// check — impossible rather than merely partial. Anything unexpected is an error naming the
/// input, never a skipped input.
pub fn verify_taproot_key_spends(tx: &Transaction, prevouts: &[TxOut]) -> Result<u32> {
    if tx.input.is_empty() {
        bail!("transaction has no inputs, so there is nothing to verify");
    }
    if prevouts.len() != tx.input.len() {
        bail!(
            "{} prevouts for {} inputs: a taproot sighash commits to all of them",
            prevouts.len(),
            tx.input.len()
        );
    }
    let secp = Secp256k1::verification_only();
    let mut cache = SighashCache::new(tx);
    for (i, txin) in tx.input.iter().enumerate() {
        let spk = &prevouts[i].script_pubkey;
        if !spk.is_p2tr() {
            bail!("input {i}: prevout is not a p2tr output ({spk:?})");
        }
        // `is_p2tr` already fixed the length at 34 and the witness version at 1.
        let output_key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])
            .with_context(|| format!("input {i}: prevout's witness program is not a valid key"))?;

        let witness = &txin.witness;
        if witness.len() != 1 {
            bail!(
                "input {i}: expected a 1-element key-spend witness, got {}",
                witness.len()
            );
        }
        let signature = bitcoin::taproot::Signature::from_slice(&witness[0])
            .with_context(|| format!("input {i}: witness element is not a taproot signature"))?;
        if signature.sighash_type != TapSighashType::Default {
            bail!(
                "input {i}: sighash type {:?}, expected Default (this wallet signs SIGHASH_DEFAULT)",
                signature.sighash_type
            );
        }

        let sighash = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), TapSighashType::Default)
            .with_context(|| format!("input {i}: recomputing the sighash"))?;
        secp.verify_schnorr(
            &signature.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .map_err(|e| {
            anyhow!("input {i}: signature does not verify against the recomputed sighash ({e})")
        })?;
    }
    Ok(tx.input.len() as u32)
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{
        key::{Keypair, TapTweak as _},
        secp256k1::SecretKey,
        Address, Network, Sequence, Witness,
    };
    use frostsnap_coordinator::{
        bitcoin::chain_sync::{ChainClient, ConnectionHandler, ElectrumConfig},
        persist::Persisted,
        settings::ElectrumEnabled,
    };
    use frostsnap_core::schnorr_fun::fun::{g, G};
    use std::process::Command;
    use std::sync::Mutex;

    const NETWORK: Network = Network::Regtest;

    /// Same shape `frostsnap_coordinator`'s own send tests use: the handler owns the
    /// receiving ends of the client's channels and must outlive every `ChainClient` call, so
    /// it is returned and held, never run. Nothing here opens a socket.
    fn fixture() -> (CoordSuperWallet, ConnectionHandler, MasterAppkey) {
        let db = Arc::new(Mutex::new(
            rusqlite::Connection::open_in_memory().expect("in-memory db"),
        ));
        let trusted = {
            let mut conn = db.lock().unwrap();
            Persisted::new(&mut *conn, NETWORK).unwrap()
        };
        let (client, handler) = ChainClient::new(
            bitcoin::constants::genesis_block(NETWORK).block_hash(),
            ElectrumConfig {
                enabled: ElectrumEnabled::None,
                primary: String::new(),
                backup: String::new(),
            },
            trusted,
            db.clone(),
        );
        let wallet = CoordSuperWallet::load_or_init(db, NETWORK, client).unwrap();
        // Fixed, so the derived addresses and therefore the fixture txids are the same
        // every run. The rig's per-device identities are the stub's business, not this one's.
        let master_appkey = MasterAppkey::derive_from_rootkey(g!(7 * G).normalize());
        (wallet, handler, master_appkey)
    }

    /// The fixture has to be spendable by the app's REAL coin selection and REAL transaction
    /// construction, not merely visible: `plan_consolidate`/`commit_send` is the path
    /// `SuperWallet::commit_send` puts in front of a signing session.
    #[test]
    fn an_injected_coin_is_spendable_by_the_real_send_path() {
        let (mut wallet, _handler, key) = fixture();
        assert_eq!(wallet.utxo_count(key), 0);

        let txid = inject_funding(&mut wallet, key, 200_000, None).unwrap();
        assert_eq!(wallet.utxo_count(key), 1, "the wallet must hold the coin");
        assert_eq!(
            wallet.list_transactions(key).len(),
            1,
            "and list it as its own transaction"
        );

        let outpoints = wallet.all_unspent_outpoints(key, 1.0);
        assert_eq!(outpoints, vec![OutPoint { txid, vout: 0 }]);

        // The real planner, the real committer, the real change allocation.
        let plan = wallet
            .plan_consolidate(key, outpoints.clone(), 2.0)
            .unwrap();
        let template = wallet
            .commit_send(&plan, std::iter::empty::<u32>())
            .unwrap();
        assert_eq!(template.inputs().len(), 1);
        assert_eq!(template.inputs()[0].outpoint(), outpoints[0]);
        assert!(template.fee().unwrap() > 0);

        // A second injection stacks rather than replacing the first.
        inject_funding(&mut wallet, key, 50_000, None).unwrap();
        assert_eq!(wallet.utxo_count(key), 2);

        // Deterministic: the same (spk, value) is the same funding txid every run.
        let (mut again, _h, key2) = fixture();
        assert_eq!(
            inject_funding(&mut again, key2, 200_000, None).unwrap(),
            txid
        );
    }

    /// A p2tr address for a key nobody in this wallet has.
    fn stranger_spk(secret: u8) -> ScriptBuf {
        let secp = Secp256k1::new();
        let keypair =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[secret; 32]).unwrap());
        Address::p2tr(&secp, keypair.x_only_public_key().0, None, NETWORK).script_pubkey()
    }

    /// A caller cannot name the output: if the funding transaction pays nothing the wallet
    /// derives, there is no coin, and injecting it anyway would leave an unspendable UTXO the
    /// send path would later choke on.
    #[test]
    fn a_funding_transaction_paying_someone_else_is_refused() {
        let (mut wallet, _handler, key) = fixture();
        let not_ours = synthetic_funding_tx(stranger_spk(9), 10_000);
        let err = inject_funding(
            &mut wallet,
            key,
            0,
            Some(bitcoin::consensus::encode::serialize_hex(&not_ours)),
        )
        .expect_err("a transaction paying a stranger is not a coin for this wallet");
        assert!(
            err.to_string()
                .contains("pays no script this wallet derives"),
            "unexpected error: {err}"
        );
        assert_eq!(wallet.utxo_count(key), 0);
    }

    /// A single-key Taproot spend, signed with `secp256k1` directly. Nothing FROST here on
    /// purpose: it pins the verifier against a signature whose correctness is independent of
    /// anything in this workspace, and it is the same vector
    /// `regtest_agrees_with_the_recomputed_sighash` hands to Bitcoin Core.
    fn signed_key_spend() -> (Transaction, Vec<TxOut>) {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let (internal_key, _) = keypair.x_only_public_key();
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Address::p2tr(&secp, internal_key, None, NETWORK).script_pubkey(),
        };
        let funding = synthetic_funding_tx(prevout.script_pubkey.clone(), 100_000);

        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding.compute_txid(),
                    vout: 0,
                },
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: prevout.script_pubkey.clone(),
            }],
        };
        let prevouts = vec![prevout];
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        // No aux randomness, so the vector is fixed run to run.
        let signature = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash.to_byte_array()),
            &keypair.tap_tweak(&secp, None).to_keypair(),
        );
        tx.input[0].witness = Witness::from_slice(&[bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        }
        .to_vec()]);
        (tx, prevouts)
    }

    /// THE MUTATIONS THAT MUST FAIL. A verifier that only ever says yes is not a check, so
    /// every way of being wrong that the app could plausibly produce is asserted to be
    /// caught: a changed amount, a changed recipient, a signature moved to another input, a
    /// missing witness, and a prevout set that does not match the transaction.
    #[test]
    fn the_verifier_rejects_every_way_of_being_wrong() {
        let (tx, prevouts) = signed_key_spend();
        assert_eq!(verify_taproot_key_spends(&tx, &prevouts).unwrap(), 1);

        let mut cheaper = tx.clone();
        cheaper.output[0].value = Amount::from_sat(98_000);
        assert!(
            verify_taproot_key_spends(&cheaper, &prevouts).is_err(),
            "a changed output amount must break the sighash"
        );

        let mut elsewhere = tx.clone();
        elsewhere.output[0].script_pubkey = stranger_spk(4);
        assert!(
            verify_taproot_key_spends(&elsewhere, &prevouts).is_err(),
            "a changed recipient must break the sighash"
        );

        let mut unwitnessed = tx.clone();
        unwitnessed.input[0].witness = Witness::default();
        assert!(verify_taproot_key_spends(&unwitnessed, &prevouts).is_err());

        // Same signature, but the prevout it is checked against says a different amount --
        // which is what a template disagreeing with the wallet would look like.
        let mut lying = prevouts.clone();
        lying[0].value = Amount::from_sat(100_001);
        assert!(verify_taproot_key_spends(&tx, &lying).is_err());

        // Two inputs, one signature: no input may be skipped.
        let mut doubled = tx.clone();
        doubled.input.push(doubled.input[0].clone());
        doubled.input[1].previous_output.vout = 1;
        doubled.input[1].witness = Witness::default();
        let mut two = prevouts.clone();
        two.push(prevouts[0].clone());
        assert!(verify_taproot_key_spends(&doubled, &two).is_err());

        // And a prevout list that does not cover the inputs is refused outright.
        assert!(verify_taproot_key_spends(&doubled, &prevouts).is_err());
    }

    /// BITCOIN CORE AS THE ARBITER of the sighash this file recomputes.
    ///
    /// `cold-snap/tools/regtest.py` brings up `bitcoin-node -regtest` on a disposable
    /// datadir, funds the very address [`signed_key_spend`] spends from, and hands the signed
    /// spend to `testmempoolaccept`. Core runs its own consensus signature check; if it
    /// accepts a transaction this file also accepts, the two agree on BIP-341. The tampered
    /// copy must be rejected by BOTH.
    ///
    /// `#[ignore]`d because it starts a daemon, so the default `cargo test` stays hermetic.
    /// It does NOT skip when the environment is missing -- it fails -- because a check that
    /// passes by not running is not a check:
    ///
    /// ```text
    /// COLDSNAP_REPO="$HOME/repos/cold-snap" \
    ///   cargo test -p rust_lib_frostsnapp --lib -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "starts bitcoin-node on regtest; set COLDSNAP_REPO to the cold-snap checkout"]
    fn regtest_agrees_with_the_recomputed_sighash() {
        let repo =
            std::env::var("COLDSNAP_REPO").expect("set COLDSNAP_REPO to the cold-snap checkout");
        let script = format!("{repo}/tools/regtest.py");
        let run = |args: &[&str]| -> (bool, String) {
            let out = Command::new("python3")
                .arg(&script)
                .args(args)
                .output()
                .expect("run regtest.py");
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).trim().to_owned(),
            )
        };

        /// Kills the node on every exit path, including a panicking assertion.
        struct Down(String);
        impl Drop for Down {
            fn drop(&mut self) {
                let _ = Command::new("python3").arg(&self.0).arg("down").status();
            }
        }

        assert!(run(&["up"]).0, "regtest.py up");
        let _down = Down(script.clone());

        // Fund the exact scriptPubKey the fixture spends, so Core holds the real prevout and
        // its acceptance is a statement about the signature rather than about missing inputs.
        let (tx, prevouts) = signed_key_spend();
        let address = Address::from_script(&prevouts[0].script_pubkey, NETWORK).unwrap();
        let (ok, funding_hex) = run(&["fund", &address.to_string(), "0.001"]);
        assert!(ok, "regtest.py fund");
        let funding: Transaction = deserialize_hex(&funding_hex).unwrap();

        // Re-point the fixture spend at the coin regtest actually created and re-sign, then
        // check the result BOTH ways.
        let vout = funding
            .output
            .iter()
            .position(|o| o.script_pubkey == prevouts[0].script_pubkey)
            .expect("regtest funded the address we asked for") as u32;
        let mut spend = tx.clone();
        spend.input[0].previous_output = OutPoint {
            txid: funding.compute_txid(),
            vout,
        };
        let real_prevouts = vec![funding.output[vout as usize].clone()];
        spend.output[0].value = real_prevouts[0].value - Amount::from_sat(1_000);
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let sighash = SighashCache::new(&spend)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&real_prevouts),
                TapSighashType::Default,
            )
            .unwrap();
        spend.input[0].witness = Witness::from_slice(&[bitcoin::taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(sighash.to_byte_array()),
                &keypair.tap_tweak(&secp, None).to_keypair(),
            ),
            sighash_type: TapSighashType::Default,
        }
        .to_vec()]);

        assert_eq!(
            verify_taproot_key_spends(&spend, &real_prevouts).unwrap(),
            1,
            "this file must accept the spend it just signed"
        );
        let hex = bitcoin::consensus::encode::serialize_hex(&spend);
        assert!(
            run(&["accept", &hex]).0,
            "Bitcoin Core must accept a spend this file accepts"
        );

        // The mutation, checked against Core too: neither side may accept it.
        let mut tampered = spend.clone();
        tampered.output[0].value -= Amount::from_sat(500);
        assert!(verify_taproot_key_spends(&tampered, &real_prevouts).is_err());
        assert!(
            !run(&[
                "accept",
                &bitcoin::consensus::encode::serialize_hex(&tampered)
            ])
            .0,
            "Bitcoin Core must reject a spend this file rejects"
        );
    }
}
