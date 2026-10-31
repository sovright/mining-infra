//! A reference implementation of the rule in `docs/integration/block-attribution.md`,
//! tested against the sample data consumers are checked with and against lines
//! from the real event writer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::coinbase::CoinbaseTelemetry;
use crate::event::EventSink;

const SAMPLE: &str = include_str!("../tests/fixtures/block_attribution_sample.jsonl");
const EXPECTED: &str = include_str!("../tests/fixtures/block_attribution_expected.json");

/// What one line says: `miner_script` and `miner_tag`. An absent field is part of it.
type Miner = (Option<String>, Option<String>);

#[derive(Debug, PartialEq, Eq)]
enum Attribution {
    Unknown,
    Miner {
        script: Option<String>,
        tag: Option<String>,
    },
    Conflict,
}

fn attribute(lines: &[Value]) -> BTreeMap<String, Attribution> {
    let mut pairs: BTreeMap<String, BTreeSet<Miner>> = BTreeMap::new();
    for line in lines {
        let Some(hash) = line["consensus_hash"].as_str() else {
            continue;
        };
        let seen = pairs.entry(hash.to_owned()).or_default();
        let field = |name: &str| line.get(name).and_then(Value::as_str).map(str::to_owned);
        let (script, tag) = (field("miner_script"), field("miner_tag"));
        let reports_a_miner = match line["event"].as_str() {
            Some("p2p_block_coinbase") => true,
            // Logs from older builds carry the fields on the receipt.
            Some("p2p_block_received") => script.is_some() || tag.is_some(),
            _ => false,
        };
        if reports_a_miner {
            seen.insert((script, tag));
        }
    }
    pairs
        .into_iter()
        .map(|(hash, seen)| {
            let mut seen = seen.into_iter();
            let attribution = match (seen.next(), seen.next()) {
                (None, _) => Attribution::Unknown,
                (Some((script, tag)), None) => Attribution::Miner { script, tag },
                (Some(_), Some(_)) => Attribution::Conflict,
            };
            (hash, attribution)
        })
        .collect()
}

fn sample() -> Vec<Value> {
    SAMPLE
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn expected() -> BTreeMap<String, Attribution> {
    let cases: BTreeMap<String, Value> = serde_json::from_str(EXPECTED).unwrap();
    cases
        .into_iter()
        .map(|(hash, case)| {
            let field = |name: &str| case[name].as_str().map(str::to_owned);
            let attribution = match case["attribution"].as_str() {
                Some("unknown") => Attribution::Unknown,
                Some("conflict") => Attribution::Conflict,
                Some("miner") => Attribution::Miner {
                    script: field("miner_script"),
                    tag: field("miner_tag"),
                },
                other => panic!("unknown attribution {other:?}"),
            };
            (hash, attribution)
        })
        .collect()
}

#[test]
fn the_sample_gives_the_documented_result_for_every_case() {
    let results = attribute(&sample());
    let expected = expected();

    assert_eq!(results.len(), 15);
    assert_eq!(results, expected);
}

/// The result depends on what was said, not on when, so a log merged from several
/// sources reads the same in any order.
#[test]
fn the_order_of_the_lines_changes_nothing() {
    let mut lines = sample();
    lines.reverse();

    assert_eq!(attribute(&lines), expected());
}

#[test]
fn repeating_every_line_changes_nothing() {
    let once = sample();
    let twice: Vec<Value> = once.iter().chain(&once).cloned().collect();

    assert_eq!(attribute(&twice), expected());
}

/// The sample is hand-written, so this pins it to what the writer really produces.
#[test]
fn the_event_writer_writes_what_the_rule_reads() {
    let log = std::env::temp_dir().join(format!(
        "sovright-p2p-attribution-{}.jsonl",
        std::process::id()
    ));
    let events = EventSink::new(Some(log.clone())).unwrap();
    let telemetry = |tag: &str| CoinbaseTelemetry {
        miner_script: Some("76a9".to_owned()),
        miner_tag: Some(tag.to_owned()),
    };

    events.p2p_block_received("peer", "01", "aa", 10).unwrap();
    events
        .p2p_block_coinbase("peer", "01", "aa", &telemetry("pool-a"))
        .unwrap();
    events
        .p2p_block_coinbase("peer", "01", "aa", &telemetry("pool-a"))
        .unwrap();
    events.p2p_block_received("peer", "02", "bb", 10).unwrap();
    events
        .p2p_block_coinbase("peer", "02", "bb", &telemetry("pool-a"))
        .unwrap();
    events
        .p2p_block_coinbase("peer", "02", "bb", &telemetry("pool-b"))
        .unwrap();
    events.p2p_block_received("peer", "03", "cc", 10).unwrap();

    let lines: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let results = attribute(&lines);

    assert_eq!(
        results["aa"],
        Attribution::Miner {
            script: Some("76a9".to_owned()),
            tag: Some("pool-a".to_owned()),
        }
    );
    assert_eq!(results["bb"], Attribution::Conflict);
    assert_eq!(results["cc"], Attribution::Unknown);
}
