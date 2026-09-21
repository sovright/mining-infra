//! FullTemplate containment must include legacy tokens and already-declared jobs.
use std::sync::Arc;
use zcash_equihash_validator::EquihashValidator;
use zcash_jd_server::{
    DeclaredJobInfo, JdServer, JdServerConfig, JdShare, JdShareErrorCode, JobDeclarationMode,
    PushSolution, SetCustomMiningJob, SetCustomMiningJobErrorCode, SubmitSharesJd,
};
use zcash_pool_common::PayoutTracker;

// Same checked-in Zcash genesis vector as pool-server/tests/block_submission_path.rs.
/// The 140-byte genesis block header.
fn genesis_header_bytes() -> [u8; 140] {
    let bytes = hex::decode(
        "04000000\
         0000000000000000000000000000000000000000000000000000000000000000\
         db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4\
         0000000000000000000000000000000000000000000000000000000000000000\
         90041358\
         ffff071f\
         5712000000000000000000000000000000000000000000000000000000000000",
    )
    .expect("valid hex");
    let mut arr = [0u8; 140];
    arr.copy_from_slice(&bytes);
    arr
}

/// The 1344-byte genesis block Equihash solution.
fn genesis_solution() -> [u8; 1344] {
    let bytes = hex::decode(
        "000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4\
         686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed0\
         45fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf605\
         8343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072\
         a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398b\
         ca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1\
         c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a57\
         0215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098\
         f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05\
         eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc54228\
         16655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1\
         a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397\
         fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec10\
         9d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50\
         cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7b\
         b8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567a\
         ffff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719ba\
         c64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb\
         66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b\
         3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073\
         e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0\
         530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07f\
         a0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c\
         8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5\
         d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec\
         5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a59\
         9c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec0\
         6ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63f\
         ef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9f\
         cc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b660\
         2b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd8\
         61b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc0\
         9b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1a\
         ec01c4a68e41ce157",
    )
    .expect("valid hex");
    let mut arr = [0u8; 1344];
    arr.copy_from_slice(&bytes);
    arr
}

fn server() -> (JdServer, Arc<PayoutTracker>) {
    let payout = Arc::new(PayoutTracker::default());
    let config = JdServerConfig {
        pool_payout_script: vec![],
        noise_enabled: false,
        ..JdServerConfig::default()
    };
    (JdServer::new(config, payout.clone()), payout)
}

async fn existing_job(server: &JdServer, mode: JobDeclarationMode) -> DeclaredJobInfo {
    let header = genesis_header_bytes();
    let token = server
        .token_manager()
        .allocate_token_with_mode("legacy-miner", mode)
        .unwrap();
    let job = DeclaredJobInfo {
        job_id: 100,
        client_id: "legacy-miner".into(),
        mode,
        channel_id: 1,
        version: u32::from_le_bytes(header[0..4].try_into().unwrap()),
        prev_hash: header[4..36].try_into().unwrap(),
        merkle_root: header[36..68].try_into().unwrap(),
        block_commitments: header[68..100].try_into().unwrap(),
        time: u32::from_le_bytes(header[100..104].try_into().unwrap()),
        bits: u32::from_le_bytes(header[104..108].try_into().unwrap()),
        coinbase_tx: vec![],
        share_target: [0xff; 32],
    };
    server.set_current_prev_hash(job.prev_hash).await;
    server
        .token_manager()
        .set_job_info(&token.token, job.clone())
        .unwrap();
    job
}

fn share(job: &DeclaredJobInfo) -> JdShare {
    JdShare {
        version: job.version,
        time: job.time,
        nonce: genesis_header_bytes()[108..140].try_into().unwrap(),
        solution: genesis_solution(),
    }
}

#[tokio::test]
async fn full_template_containment_rejects_custom_declaration() {
    let (server, payout) = server();
    let token = server
        .token_manager()
        .allocate_token_with_mode("legacy-miner", JobDeclarationMode::FullTemplate)
        .unwrap();
    server.set_current_prev_hash([0xaa; 32]).await;
    // A parseable legacy transparent coinbase accepted by the existing custom path.
    let mut coinbase = 1u32.to_le_bytes().to_vec();
    coinbase.push(1);
    coinbase.extend_from_slice(&[0; 32]);
    coinbase.extend_from_slice(&u32::MAX.to_le_bytes());
    coinbase.extend_from_slice(&[1, 0]);
    coinbase.extend_from_slice(&u32::MAX.to_le_bytes());
    coinbase.push(1);
    coinbase.extend_from_slice(&0u64.to_le_bytes());
    coinbase.extend_from_slice(&[1, 0x51]);
    coinbase.extend_from_slice(&0u32.to_le_bytes());
    let error = server
        .handle_declare_job(SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            mining_job_token: token.token.clone(),
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            coinbase_tx: coinbase,
            time: 1_700_000_000,
            bits: 0x1d00ffff,
        })
        .await
        .expect_err("FullTemplate token must not bypass the gate via custom declaration");
    assert_eq!(error.error_code, SetCustomMiningJobErrorCode::Other);
    assert!(
        error
            .error_message
            .starts_with("FullTemplate is unavailable:")
    );
    assert!(server.token_manager().get_job_info(&token.token).is_err());
    assert!(payout.get_stats(&"legacy-miner".into()).is_none());
}

#[tokio::test]
async fn full_template_containment_rejects_valid_existing_job_share() {
    let (server, payout) = server();
    let job = existing_job(&server, JobDeclarationMode::FullTemplate).await;
    // Prove rejection is authorization, not a bad solution/target fixture.
    EquihashValidator::new()
        .verify_share(
            &genesis_header_bytes(),
            &genesis_solution(),
            &job.share_target,
        )
        .unwrap();
    let response = server
        .handle_submit_shares_jd(SubmitSharesJd {
            channel_id: 1,
            request_id: 7,
            job_id: job.job_id,
            shares: vec![share(&job), share(&job)],
        })
        .await;
    assert_eq!(
        response.accepted, 0,
        "unavailable FullTemplate jobs must never earn credit"
    );
    assert_eq!(response.rejected, 2);
    assert_eq!(
        response.first_error_code,
        JdShareErrorCode::StaleJob.as_u8()
    );
    assert_eq!((response.channel_id, response.request_id), (1, 7));
    assert!(payout.get_stats(&job.client_id).is_none());
}

#[tokio::test]
async fn full_template_containment_rejects_valid_existing_job_solution() {
    let (server, payout) = server();
    let job = existing_job(&server, JobDeclarationMode::FullTemplate).await;
    let share = share(&job);
    let error = server
        .handle_push_solution(PushSolution::new(
            job.channel_id,
            job.job_id,
            job.version,
            job.time,
            share.nonce,
            share.solution,
        ))
        .await
        .expect_err("FullTemplate block solution must not bypass containment");
    assert!(error.to_string().contains("FullTemplate is unavailable:"));
    assert!(payout.get_stats(&job.client_id).is_none());
}

#[tokio::test]
async fn coinbase_only_existing_job_valid_share_still_credits_once() {
    let (server, payout) = server();
    let job = existing_job(&server, JobDeclarationMode::CoinbaseOnly).await;
    let response = server
        .handle_submit_shares_jd(SubmitSharesJd {
            channel_id: 1,
            request_id: 7,
            job_id: job.job_id,
            shares: vec![share(&job), share(&job)],
        })
        .await;
    assert_eq!(response.accepted, 1);
    assert_eq!(response.rejected, 1);
    assert_eq!(
        response.first_error_code,
        JdShareErrorCode::Duplicate.as_u8()
    );
    assert_eq!(payout.get_stats(&job.client_id).unwrap().total_shares, 1);
}
