//! Example: Fetch a block template from Zebra
//!
//! Usage: cargo run --example fetch_template -- [zebra_url]
//! Default: http://127.0.0.1:8232

use zcash_template_provider::{TemplateProvider, TemplateProviderConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let zebra_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8232".to_string());

    println!("Connecting to Zebra at {}", zebra_url);

    let config = TemplateProviderConfig {
        zebra_url,
        submit_url: None,
        poll_interval_ms: 1000,
    };

    let provider = TemplateProvider::new(config)?;

    match provider.fetch_template().await {
        Ok(template) => {
            println!("\n=== Block Template ===");
            println!("Template ID: {}", template.template_id);
            println!("Height: {}", template.height);
            println!("Version: {}", template.header.version);
            println!("Prev Hash: {}", template.header.prev_hash.to_hex());
            println!("Merkle Root: {}", template.header.merkle_root.to_hex());
            println!(
                "Block Commitments: {}",
                template.header.hash_block_commitments.to_hex()
            );
            println!("Time: {}", template.header.time);
            println!("Bits: 0x{:08x}", template.header.bits);
            println!("Target: {}", template.target.to_hex());
            println!("Transactions: {}", template.transactions.len());
            println!("Total Fees: {} zatoshis", template.total_fees);
            println!("Coinbase Size: {} bytes", template.coinbase.len());

            println!("\n=== Header (140 bytes hex) ===");
            let header_bytes = template.header.serialize();
            println!("{}", hex::encode(header_bytes));
        }
        Err(e) => {
            eprintln!("Failed to fetch template: {}", e);
            eprintln!("\nMake sure Zebra is running with RPC enabled.");
            std::process::exit(1);
        }
    }

    Ok(())
}
