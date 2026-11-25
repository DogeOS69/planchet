//! Read-only node path: verify-block node http://127.0.0.1:18443 regtest 0
//! Offline binary wire bytes: verify-block offline /path/block.bin [expected-block-hash]
use planchet_provider::{
    Provider, check_raw_block,
    transport::{BasicAuth, HttpConfig, HttpTransport},
};
use std::{error::Error, io::Read};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("node") if args.len() == 4 => {
            let network = args[2].parse()?;
            let height: u64 = args[3].parse()?;
            let user = std::env::var("PLANCHET_RPC_USER").ok();
            let password = std::env::var("PLANCHET_RPC_PASSWORD").ok();
            let auth = match (user, password) {
                (None, None) => None,
                (Some(user), Some(password)) => Some(BasicAuth::new(user, password)),
                _ => return Err("set both PLANCHET_RPC_USER and PLANCHET_RPC_PASSWORD, or neither".into()),
            };
            let transport = HttpTransport::new(&args[1], auth, HttpConfig::default())?;
            let provider = Provider::new(transport);
            provider.validate_network(network).await?;
            let check = provider.check_block_at_height(height).await?;
            println!("network={network} height={height} block_id={} bytes={} merkle=ok anchor=stable", check.block_hash, check.byte_len);
        }
        Some("offline") if (2..=3).contains(&args.len()) => {
            let expected = args.get(2).map(|s| s.parse()).transpose()?;
            const LIMIT: u64 = 64 * 1024 * 1024;
            let mut bytes = Vec::new();
            std::fs::File::open(&args[1])?.take(LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > LIMIT { return Err("raw block file exceeds 64 MiB".into()); }
            let check = check_raw_block(&bytes, expected)?;
            println!("block_id={} bytes={} merkle=ok", check.block_hash, check.byte_len);
        }
        _ => return Err("usage: verify-block node <http-url> <mainnet|testnet|regtest> <height> | offline <raw-block-file> [expected-block-hash]".into()),
    }
    Ok(())
}
