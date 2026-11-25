//! Offline one-input P2PKH payment. Input minus payment is the explicitly bounded fee.
use planchet_consensus::sighash::SighashType;
use planchet_consensus::{
    DecodeLimits,
    transaction::{PaymentBudget, Prevout, Transaction},
};
use planchet_primitives::OutPoint;
use planchet_psbt::PsbtV0;
use planchet_signer::{DigestSigner, LocalSigner, SignRequest};
use std::{
    env,
    error::Error,
    fs,
    io::{self, Read},
};
use zeroize::Zeroizing;

fn decode_hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 6 {
        return Err("usage: offline-p2pkh PARENT_HEX_FILE VOUT DESTINATION_SCRIPT_HEX PAYMENT_KOINU MAX_FEE_KOINU MIN_RATE_KOINU_PER_KVB; provide the 32-byte signing key as hex on stdin".into());
    }
    let parent = Transaction::decode_exact(
        &decode_hex(&fs::read_to_string(&args[0])?)?,
        DecodeLimits::default(),
    )?;
    let prevout = Prevout::from_parent(OutPoint::new(parent.txid(), args[1].parse()?), &parent)?;
    let budget = PaymentBudget {
        max_fee: args[4].parse()?,
        min_fee_rate_koinu_per_kvb: args[5].parse()?,
    };
    let mut secret_text = Zeroizing::new(String::new());
    io::stdin().read_to_string(&mut secret_text)?;
    let decoded_key = Zeroizing::new(decode_hex(&secret_text)?);
    if decoded_key.len() != 32 {
        return Err("expected exactly 32 key bytes".into());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded_key);
    let signer = LocalSigner::from_bytes(&key)?;
    let unsigned = Transaction::builder(1, 0)
        .spend(prevout.outpoint, u32::MAX)
        .pay(decode_hex(&args[2])?, args[3].parse()?)
        .finish()?;
    let mut psbt = PsbtV0::from_unsigned(unsigned)?;
    psbt.attach_parent(0, &parent)?;
    let prevouts = [prevout];
    let request = psbt.sign_request(
        0,
        &prevouts,
        signer.public_key().as_bytes(),
        SighashType::All,
        budget,
    )?;
    let signature = signer.sign_prehash(&SignRequest::from_psbt(&request)?)?;
    psbt.insert_verified_signature(
        &request,
        signature.public_key.as_bytes(),
        signature.signature.as_der(),
        signature.sighash_type,
    )?;
    let signed = psbt.finalize_p2pkh(&prevouts, budget)?;
    let checked = psbt.extract(&prevouts, budget)?;
    if signed != checked {
        return Err("finalization/extraction mismatch".into());
    }
    for byte in signed.encode() {
        print!("{byte:02x}");
    }
    println!();
    eprintln!(
        "txid={} bytes={} fee_koinu={}",
        signed.transaction().txid(),
        signed.summary().transaction_bytes,
        signed.summary().fee
    );
    Ok(())
}
