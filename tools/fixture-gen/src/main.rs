//! Generates the signed DLC test vectors in `fixtures/`.
//!
//! Every vector is a real contract made with `ddk::contract`: an offer from
//! `create_offer`, an accept from `accept_offer`, a sign message from the
//! offerer's funding witnesses, and a funding transaction that
//! `finalize_sign_with_funding_signatures` completes. That last step runs DDK's
//! own `verify_signed_contract`, so a vector that is written verifies under DDK.
//!
//! Keys, scripts, serial ids and temporary contract ids are fixed. CET adaptor
//! signatures use fresh randomness, so regenerating changes their bytes and
//! every value derived from them, but not the contract terms.
//!
//! ```text
//! cargo run -p fixture-gen -- [OUT_DIR]     # OUT_DIR defaults to fixtures
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use ddk::contract::{
    AcceptOfferParams, CreateOfferParams, PartyParams, accept_offer, advanced,
    chain_hash_from_network, create_dlc_transactions, create_offer, funding_input,
};
use ddk_dlc::secp256k1_zkp::{All, Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use ddk_manager::contract::numerical_descriptor::NumericalDescriptor;
use ddk_manager::payout_curve::{
    PayoutFunction, PayoutFunctionPiece, PayoutPoint, PolynomialPayoutCurvePiece, RoundingInterval,
    RoundingIntervals,
};
use ddk_messages::contract_msgs::{
    ContractDescriptor, ContractInfo, ContractInfoInner, ContractOutcome, DisjointContractInfo,
    EnumeratedContractDescriptor, NumericOutcomeContractDescriptor, SingleContractInfo,
};
use ddk_messages::oracle_msgs::{
    DigitDecompositionEventDescriptor, EnumEventDescriptor, EventDescriptor, MultiOracleInfo,
    OracleAnnouncement, OracleAttestation, OracleEvent, OracleInfo, SingleOracleInfo,
    tagged_announcement_msg, tagged_attestation_msg,
};
use ddk_messages::{
    AcceptDlc, FundingInput, FundingSignatures, OfferDlc, OverrideOutcome, PayoutScriptOverride,
    PayoutScriptOverrides, SignDlc, TlvRecord,
};
use ddk_trie::OracleNumericInfo;
use lightning::util::ser::Writeable;
use serde_json::{Value, json};

/// Oracle event maturity of every vector: 2026-01-01T00:00:00Z.
const MATURITY: u32 = 1_767_225_600;
/// The accepting party's clock: one day before maturity.
const NOW: u64 = MATURITY as u64 - 86_400;
/// Refund delay after maturity, and the accepter's timeout policy.
const WEEK: u32 = 604_800;
const FEE_RATE_PER_VB: u64 = 2;
const TOTAL: Amount = Amount::from_sat(100_000);
const HALF: Amount = Amount::from_sat(50_000);
const UTXO_VALUE: Amount = Amount::from_sat(150_000);
const P2WPKH_MAX_WITNESS_LEN: u16 = 108;
/// Binary digits of the numeric oracle event: values 0 to 1023.
const NB_DIGITS: u16 = 10;
const DDK_VERSION: &str = "2.0.0-rc.10";

fn main() -> Result<()> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "fixtures".to_string()),
    );
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let secp = Secp256k1::new();
    for fixture in fixtures(&secp)? {
        let path = out_dir.join(format!("{}.json", fixture.name));
        let text = serde_json::to_string_pretty(&fixture.to_json())? + "\n";
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// A deterministic secret key for a label.
fn key(label: &str) -> Result<SecretKey> {
    let digest = sha256::Hash::hash(format!("dlc-verify fixture key/{label}").as_bytes());
    SecretKey::from_slice(digest.as_byte_array()).context("fixture key out of range")
}

fn p2wpkh(secp: &Secp256k1<All>, secret_key: &SecretKey) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&CompressedPublicKey(secret_key.public_key(secp)).wpubkey_hash())
}

/// One side of a contract: a DLC funding key, a wallet key holding the funding
/// UTXOs, and distinct payout and change scripts.
struct Party {
    funding_key: SecretKey,
    wallet_key: SecretKey,
    funding_inputs: Vec<FundingInput>,
    payout_spk: ScriptBuf,
    payout_serial_id: u64,
    change_spk: ScriptBuf,
    change_serial_id: u64,
}

impl Party {
    /// `role` names the keys; `serial_base` spaces this party's serial ids.
    fn new(secp: &Secp256k1<All>, role: &str, serial_base: u64, utxos: usize) -> Result<Self> {
        let wallet_key = key(&format!("{role}/wallet"))?;
        let wallet_spk = p2wpkh(secp, &wallet_key);
        let funding_inputs = (0..utxos)
            .map(|index| {
                let previous = previous_transaction(role, index, UTXO_VALUE, wallet_spk.clone());
                funding_input(
                    &previous,
                    0,
                    Some(serial_base + 1 + index as u64),
                    u32::MAX,
                    P2WPKH_MAX_WITNESS_LEN,
                    ScriptBuf::new(),
                )
                .map_err(|e| anyhow!("funding input: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            funding_key: key(&format!("{role}/funding"))?,
            wallet_key,
            funding_inputs,
            payout_spk: p2wpkh(secp, &key(&format!("{role}/payout"))?),
            payout_serial_id: serial_base + 10,
            change_spk: p2wpkh(secp, &key(&format!("{role}/change"))?),
            change_serial_id: serial_base + 20,
        })
    }

    fn params(&self, secp: &Secp256k1<All>) -> PartyParams {
        PartyParams {
            funding_pubkey: self.funding_key.public_key(secp),
            funding_inputs: self.funding_inputs.clone(),
            payout_spk: self.payout_spk.clone(),
            payout_serial_id: Some(self.payout_serial_id),
            change_spk: self.change_spk.clone(),
            change_serial_id: Some(self.change_serial_id),
        }
    }
}

/// A transaction paying `value` to `script_pubkey`, standing in for a wallet UTXO.
fn previous_transaction(
    role: &str,
    index: usize,
    value: Amount,
    script_pubkey: ScriptBuf,
) -> Transaction {
    let seed = sha256::Hash::hash(format!("dlc-verify fixture utxo/{role}/{index}").as_bytes());
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(seed.to_byte_array()),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey,
        }],
    }
}

/// A test oracle with a fixed key and fixed nonces per event.
struct Oracle {
    name: String,
}

impl Oracle {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    fn keypair(&self, secp: &Secp256k1<All>) -> Result<Keypair> {
        Ok(Keypair::from_secret_key(
            secp,
            &key(&format!("oracle/{}", self.name))?,
        ))
    }

    fn nonce(&self, event_id: &str, index: usize) -> Result<SecretKey> {
        key(&format!("oracle/{}/{event_id}/nonce/{index}", self.name))
    }

    fn announce(
        &self,
        secp: &Secp256k1<All>,
        event_id: &str,
        event_descriptor: EventDescriptor,
        nonce_count: usize,
    ) -> Result<OracleAnnouncement> {
        let keypair = self.keypair(secp)?;
        let oracle_nonces = (0..nonce_count)
            .map(|index| {
                let nonce = Keypair::from_secret_key(secp, &self.nonce(event_id, index)?);
                Ok(XOnlyPublicKey::from_keypair(&nonce).0)
            })
            .collect::<Result<Vec<_>>>()?;
        let oracle_event = OracleEvent {
            oracle_nonces,
            event_maturity_epoch: MATURITY,
            event_descriptor,
            event_id: event_id.to_string(),
        };
        Ok(OracleAnnouncement {
            announcement_signature: secp
                .sign_schnorr_no_aux_rand(&tagged_announcement_msg(&oracle_event), &keypair),
            oracle_public_key: XOnlyPublicKey::from_keypair(&keypair).0,
            oracle_event,
        })
    }

    fn attest(
        &self,
        secp: &Secp256k1<All>,
        event_id: &str,
        outcomes: Vec<String>,
    ) -> Result<OracleAttestation> {
        let keypair = self.keypair(secp)?;
        let signatures = outcomes
            .iter()
            .enumerate()
            .map(|(index, outcome)| {
                Ok(ddk_dlc::secp_utils::schnorrsig_sign_with_nonce(
                    secp,
                    &tagged_attestation_msg(outcome),
                    &keypair,
                    &self.nonce(event_id, index)?.secret_bytes(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(OracleAttestation {
            event_id: event_id.to_string(),
            oracle_public_key: XOnlyPublicKey::from_keypair(&keypair).0,
            signatures,
            outcomes,
        })
    }
}

const ENUM_OUTCOMES: [&str; 3] = ["up", "down", "flat"];

fn enum_event() -> EventDescriptor {
    EventDescriptor::EnumEvent(EnumEventDescriptor {
        outcomes: ENUM_OUTCOMES.iter().map(|o| o.to_string()).collect(),
    })
}

/// "up" pays the offerer everything, "down" the accepter, "flat" splits it.
fn enum_descriptor(total: Amount) -> ContractDescriptor {
    let payout = |outcome: &str, offer_payout: Amount| ContractOutcome {
        outcome: outcome.to_string(),
        offer_payout,
    };
    ContractDescriptor::EnumeratedContractDescriptor(EnumeratedContractDescriptor {
        payouts: vec![
            payout("up", total),
            payout("down", Amount::ZERO),
            payout("flat", total / 2),
        ],
    })
}

fn digit_event() -> EventDescriptor {
    EventDescriptor::DigitDecompositionEvent(DigitDecompositionEventDescriptor {
        base: 2,
        is_signed: false,
        unit: "usd".to_string(),
        precision: 0,
        nb_digits: NB_DIGITS,
    })
}

fn max_value() -> u64 {
    (1u64 << NB_DIGITS) - 1
}

/// The offerer is paid nothing up to 300, everything from 700, and linearly
/// in between; payouts round to 10,000 sats.
fn numerical_descriptor(total: Amount) -> Result<NumericalDescriptor> {
    let point = |event_outcome: u64, outcome_payout: Amount| PayoutPoint {
        event_outcome,
        outcome_payout,
        extra_precision: 0,
    };
    let piece = |points: Vec<PayoutPoint>| -> Result<PayoutFunctionPiece> {
        Ok(PayoutFunctionPiece::PolynomialPayoutCurvePiece(
            PolynomialPayoutCurvePiece::new(points).map_err(|e| anyhow!("curve piece: {e}"))?,
        ))
    };
    let payout_function = PayoutFunction::new(vec![
        piece(vec![point(0, Amount::ZERO), point(300, Amount::ZERO)])?,
        piece(vec![point(300, Amount::ZERO), point(700, total)])?,
        piece(vec![point(700, total), point(max_value(), total)])?,
    ])
    .map_err(|e| anyhow!("payout function: {e}"))?;
    Ok(NumericalDescriptor {
        payout_function,
        rounding_intervals: RoundingIntervals {
            intervals: vec![RoundingInterval {
                begin_interval: 0,
                rounding_mod: 10_000,
            }],
        },
        difference_params: None,
        oracle_numeric_infos: OracleNumericInfo {
            base: 2,
            nb_digits: vec![NB_DIGITS as usize],
        },
    })
}

fn single(total: Amount, inner: ContractInfoInner) -> ContractInfo {
    ContractInfo::SingleContractInfo(SingleContractInfo {
        total_collateral: total,
        contract_info: inner,
    })
}

fn single_oracle(announcement: OracleAnnouncement) -> OracleInfo {
    OracleInfo::Single(SingleOracleInfo {
        oracle_announcement: announcement,
    })
}

/// Binary digits of `value`, most significant first, as the oracle attests them.
fn digits(value: u64) -> Vec<String> {
    (0..NB_DIGITS)
        .rev()
        .map(|position| ((value >> position) & 1).to_string())
        .collect()
}

/// A liquidator's script: belongs to neither party.
fn third_party_script(secp: &Secp256k1<All>) -> Result<ScriptBuf> {
    Ok(p2wpkh(secp, &key("third-party/liquidator")?))
}

/// What to build.
struct Spec {
    name: &'static str,
    description: &'static str,
    network: Network,
    contract_info: ContractInfo,
    offer_collateral: Amount,
    offer_utxos: usize,
    accept_utxos: usize,
    contract_flags: u8,
    overrides: Option<PayoutScriptOverrides>,
    attestations: Vec<OracleAttestation>,
}

/// A built and verified contract.
struct Fixture {
    name: &'static str,
    description: &'static str,
    network: Network,
    offer: OfferDlc,
    accept: AcceptDlc,
    sign: SignDlc,
    funding_transaction: Transaction,
    attestations: Vec<OracleAttestation>,
    offerer_funding_pubkey: PublicKey,
    accepter_funding_pubkey: PublicKey,
}

fn build(secp: &Secp256k1<All>, spec: Spec) -> Result<Fixture> {
    let offerer = Party::new(secp, "offerer", 100, spec.offer_utxos)?;
    let accepter = Party::new(secp, "accepter", 200, spec.accept_utxos)?;
    let temporary_contract_id =
        sha256::Hash::hash(format!("dlc-verify fixture/{}", spec.name).as_bytes()).to_byte_array();
    let mut offer = create_offer(CreateOfferParams {
        chain_hash: chain_hash_from_network(spec.network),
        temporary_contract_id: Some(temporary_contract_id),
        contract_info: spec.contract_info,
        offer_collateral: spec.offer_collateral,
        party: offerer.params(secp),
        fund_output_serial_id: Some(50),
        fee_rate_per_vb: FEE_RATE_PER_VB,
        cet_locktime: Some(MATURITY),
        refund_locktime: MATURITY + WEEK,
        contract_flags: spec.contract_flags,
    })
    .map_err(|e| anyhow!("{}: create_offer: {e}", spec.name))?;
    if let Some(overrides) = &spec.overrides {
        offer.tlvs.set(overrides);
    }

    let accept = accept_offer(
        &offer,
        AcceptOfferParams {
            party: accepter.params(secp),
            min_timeout_interval: WEEK,
            max_timeout_interval: WEEK,
            now_unix: NOW,
        },
        &accepter.funding_key,
    )
    .map_err(|e| anyhow!("{}: accept_offer: {e}", spec.name))?
    .accept;

    let transactions = create_dlc_transactions(&offer, &accept)
        .map_err(|e| anyhow!("{}: create_dlc_transactions: {e}", spec.name))?;
    let offer_witnesses = funding_witnesses(&transactions.fund, &offerer)?;
    let sign = advanced::sign_accept_with_funding_signatures(
        &offer,
        &accept,
        &offerer.funding_key,
        offer_witnesses,
    )
    .map_err(|e| anyhow!("{}: sign_accept: {e}", spec.name))?
    .sign;
    let accept_witnesses = funding_witnesses(&transactions.fund, &accepter)?;
    let funding_transaction =
        advanced::finalize_sign_with_funding_signatures(&offer, &accept, &sign, accept_witnesses)
            .map_err(|e| anyhow!("{}: finalize_sign: {e}", spec.name))?;

    Ok(Fixture {
        name: spec.name,
        description: spec.description,
        network: spec.network,
        offer,
        accept,
        sign,
        funding_transaction,
        attestations: spec.attestations,
        offerer_funding_pubkey: offerer.funding_key.public_key(secp),
        accepter_funding_pubkey: accepter.funding_key.public_key(secp),
    })
}

/// Signs each of `party`'s funding inputs, in message order.
fn funding_witnesses(fund: &Transaction, party: &Party) -> Result<FundingSignatures> {
    let mut witnesses = Vec::new();
    for input in &party.funding_inputs {
        let previous: Transaction = bitcoin::consensus::deserialize(&input.prev_tx)?;
        let outpoint = OutPoint {
            txid: previous.compute_txid(),
            vout: input.prev_tx_vout,
        };
        let value = previous
            .output
            .get(input.prev_tx_vout as usize)
            .map(|output| output.value)
            .ok_or_else(|| anyhow!("missing previous output"))?;
        let index = fund
            .input
            .iter()
            .position(|tx_input| tx_input.previous_output == outpoint)
            .ok_or_else(|| anyhow!("funding transaction does not spend {outpoint}"))?;
        witnesses.push(
            advanced::sign_p2wpkh_funding_input(fund, index, value, &party.wallet_key)
                .map_err(|e| anyhow!("signing funding input: {e}"))?,
        );
    }
    Ok(FundingSignatures {
        funding_signatures: witnesses,
    })
}

impl Fixture {
    fn to_json(&self) -> Value {
        let network = match self.network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        };
        let attestations: Vec<Value> = self
            .attestations
            .iter()
            .map(|attestation| {
                json!({
                    "event_id": attestation.event_id,
                    "oracle_public_key": attestation.oracle_public_key.to_string(),
                    "outcomes": attestation.outcomes,
                    "hex": attestation.to_tlv_hex(),
                })
            })
            .collect();
        json!({
            "name": self.name,
            "description": self.description,
            "generator": format!("tools/fixture-gen (ddk {DDK_VERSION})"),
            "network": network,
            "now": NOW,
            "offerer_funding_pubkey": self.offerer_funding_pubkey.to_string(),
            "accepter_funding_pubkey": self.accepter_funding_pubkey.to_string(),
            "offer": hex::encode(self.offer.encode()),
            "accept": hex::encode(self.accept.encode()),
            "sign": hex::encode(self.sign.encode()),
            "funding_transaction": bitcoin::consensus::encode::serialize_hex(&self.funding_transaction),
            "attestations": attestations,
        })
    }
}

fn fixtures(secp: &Secp256k1<All>) -> Result<Vec<Fixture>> {
    let alice = Oracle::new("alice");
    let bob = Oracle::new("bob");
    let carol = Oracle::new("carol");
    let enum_inner = |oracle: &Oracle, event_id: &str| -> Result<ContractInfoInner> {
        Ok(ContractInfoInner {
            contract_descriptor: enum_descriptor(TOTAL),
            oracle_info: single_oracle(oracle.announce(secp, event_id, enum_event(), 1)?),
        })
    };
    let numeric_inner = |oracle: &Oracle, event_id: &str| -> Result<ContractInfoInner> {
        Ok(ContractInfoInner {
            contract_descriptor: ContractDescriptor::NumericOutcomeContractDescriptor(
                NumericOutcomeContractDescriptor::from(&numerical_descriptor(TOTAL)?),
            ),
            oracle_info: single_oracle(oracle.announce(
                secp,
                event_id,
                digit_event(),
                NB_DIGITS as usize,
            )?),
        })
    };
    let attest = |oracle: &Oracle, event_id: &str, outcome: &str| {
        oracle.attest(secp, event_id, vec![outcome.to_string()])
    };

    // The numeric override covers exactly the values of the first CET, where
    // the accepter is paid everything.
    let first_cet = numerical_descriptor(TOTAL)?
        .get_range_payouts(TOTAL)
        .map_err(|e| anyhow!("range payouts: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("numeric descriptor has no CETs"))?;
    let first_cet_end = (first_cet.start + first_cet.count - 1) as u64;
    if first_cet.payout.accept != TOTAL {
        bail!("the first numeric CET should pay the accepter everything");
    }

    let specs = vec![
        Spec {
            name: "enum-dual-funded",
            description: "Enum contract (up, down, flat), one oracle, both parties fund half.",
            network: Network::Regtest,
            contract_info: single(TOTAL, enum_inner(&alice, "enum-dual-funded")?),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0,
            overrides: None,
            attestations: vec![attest(&alice, "enum-dual-funded", "down")?],
        },
        Spec {
            name: "enum-single-funded",
            description: "Enum contract funded by the offerer alone; the accepter adds no inputs. Mainnet chain hash.",
            network: Network::Bitcoin,
            contract_info: single(TOTAL, enum_inner(&alice, "enum-single-funded")?),
            offer_collateral: TOTAL,
            offer_utxos: 2,
            accept_utxos: 0,
            contract_flags: 0,
            overrides: None,
            attestations: vec![attest(&alice, "enum-single-funded", "up")?],
        },
        Spec {
            name: "enum-refund-to-accepter",
            description: "Enum contract with contract flag 0x01: the refund pays the whole collateral to the accepter. Testnet4 chain hash.",
            network: Network::Testnet4,
            contract_info: single(TOTAL, enum_inner(&alice, "enum-refund-to-accepter")?),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0x01,
            overrides: None,
            attestations: vec![],
        },
        Spec {
            name: "enum-payout-override",
            description: "Enum contract whose \"down\" CET pays the accepter's share to a third party (a liquidator) through payout-script-override TLV 65005.",
            network: Network::Regtest,
            contract_info: single(TOTAL, enum_inner(&alice, "enum-payout-override")?),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0,
            overrides: Some(PayoutScriptOverrides {
                overrides: vec![PayoutScriptOverride {
                    outcome: OverrideOutcome::Enum {
                        outcome: "down".to_string(),
                    },
                    script_pubkey: third_party_script(secp)?,
                }],
            }),
            attestations: vec![attest(&alice, "enum-payout-override", "down")?],
        },
        Spec {
            name: "numeric-dual-funded",
            description: "Numeric contract on a 10-digit binary oracle event, payouts rounded to 10,000 sats.",
            network: Network::Regtest,
            contract_info: single(TOTAL, numeric_inner(&alice, "numeric-dual-funded")?),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0,
            overrides: None,
            attestations: vec![alice.attest(secp, "numeric-dual-funded", digits(512))?],
        },
        Spec {
            name: "numeric-payout-override",
            description: "Numeric contract whose lowest CET (accepter paid everything) pays a third party through TLV 65005.",
            network: Network::Regtest,
            contract_info: single(TOTAL, numeric_inner(&alice, "numeric-payout-override")?),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0,
            overrides: Some(PayoutScriptOverrides {
                overrides: vec![PayoutScriptOverride {
                    outcome: OverrideOutcome::Numeric {
                        start: first_cet.start as u64,
                        end: first_cet_end,
                    },
                    script_pubkey: third_party_script(secp)?,
                }],
            }),
            attestations: vec![alice.attest(secp, "numeric-payout-override", digits(100))?],
        },
        Spec {
            name: "enum-multi-oracle",
            description: "Enum contract settled by any 2 of 3 oracles.",
            network: Network::Regtest,
            contract_info: single(
                TOTAL,
                ContractInfoInner {
                    contract_descriptor: enum_descriptor(TOTAL),
                    oracle_info: OracleInfo::Multi(MultiOracleInfo {
                        threshold: 2,
                        oracle_announcements: vec![
                            alice.announce(secp, "enum-multi-oracle", enum_event(), 1)?,
                            bob.announce(secp, "enum-multi-oracle", enum_event(), 1)?,
                            carol.announce(secp, "enum-multi-oracle", enum_event(), 1)?,
                        ],
                        oracle_params: None,
                    }),
                },
            ),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0,
            overrides: None,
            attestations: vec![
                attest(&alice, "enum-multi-oracle", "flat")?,
                attest(&carol, "enum-multi-oracle", "flat")?,
            ],
        },
        Spec {
            name: "disjoint-enum-numeric",
            description: "Disjoint contract: an enum contract info on one oracle and a numeric one on another.",
            network: Network::Regtest,
            contract_info: ContractInfo::DisjointContractInfo(DisjointContractInfo {
                total_collateral: TOTAL,
                contract_infos: vec![
                    enum_inner(&alice, "disjoint-enum")?,
                    numeric_inner(&bob, "disjoint-numeric")?,
                ],
            }),
            offer_collateral: HALF,
            offer_utxos: 1,
            accept_utxos: 1,
            contract_flags: 0,
            overrides: None,
            attestations: vec![bob.attest(secp, "disjoint-numeric", digits(800))?],
        },
    ];
    specs.into_iter().map(|spec| build(secp, spec)).collect()
}
