//! Compute a relay `WtxId` directly from a transaction's raw wire bytes.
//!
//! The origin tx cache is a reverse `payload -> wtxid` index built only from the
//! transactions the ingress peers relayed on the P2P network; it cannot derive a
//! wtxid for a block transaction it never saw. The compact *skeleton* therefore
//! has to prefill every such cache-miss transaction, inflating the object it was
//! designed to shrink. This module closes that gap: it parses a raw transaction
//! with `zcash_primitives` and computes the ZIP-244 txid and authorizing-data
//! commitment (auth digest), yielding the exact 64-byte `WtxId` the sidecar
//! would build from Zebra's reported (display-order) `txid`/`authdigest`. A
//! skeleton short_id computed here therefore matches what receivers resolve
//! against their own mempools.
//!
//! Only v5 (ZIP-244) transactions have an auth digest, so only they can be
//! short_id'd from bytes; pre-v5 transactions return `None` (left prefilled),
//! matching the sidecar mempool's `prepare_insert`, which also skips pre-v5.
//!
//! BYTE ORDER (load-bearing): `zcash_primitives` stores both the txid and the
//! auth commitment in internal (wire) byte order -- the raw BLAKE2b digest
//! bytes, NOT the reversed "display" order Zebra's RPC reports.
//! `sovright_relay::{TxId, AuthDigest}` also store wire order (the sidecar's
//! `wtxid_from_display_hex` reverses Zebra's display hex back to wire). So both
//! map across with NO reversal. This equivalence is proven byte-for-byte against
//! a real ZIP-244 test vector in the tests below, comparing directly to the
//! sidecar's `wtxid_from_display_hex`.

use std::io::Cursor;

use sovright_relay::{AuthDigest, TxId, WtxId};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

/// Mainnet consensus branch id handed to the transaction reader.
///
/// For v5 (ZIP-244) transactions -- the ONLY version this module short_ids --
/// `zcash_primitives::transaction::Transaction::read` reads the consensus branch
/// id out of the transaction bytes themselves and computes both the txid and the
/// auth digest from that embedded value. The `branch_id` argument is therefore
/// IGNORED for v5 and never affects the returned `WtxId` (see the
/// `branch_id_argument_is_ignored_for_v5` test, which proves it). It is threaded
/// only to satisfy the reader API (and to parse hypothetical pre-v5
/// transactions, which are then rejected regardless of the branch id).
///
/// Because it never influences any wtxid we emit, deriving it per-block from the
/// BIP34 coinbase height would be pure ceremony with a maintenance burden, so we
/// use this documented constant. Bump it at each network upgrade anyway, to keep
/// the documented intent aligned with mainnet.
pub const SOVRIGHT_P2P_CONSENSUS_BRANCH_ID: BranchId = BranchId::Nu6;

/// Parse `tx_bytes` and, for a v5 (ZIP-244) transaction, return its relay
/// `WtxId` = wire-order `txid (32) || auth_digest (32)`, identical to what the
/// sidecar builds from Zebra's display-order `txid`/`authdigest`.
///
/// Returns `None` for:
/// - pre-v5 transactions (no auth digest -- matches the sidecar mempool sync),
/// - any input that fails to parse or has trailing bytes (malformed).
///
/// Never panics.
pub fn wtxid_from_tx_bytes(tx_bytes: &[u8], branch_id: BranchId) -> Option<WtxId> {
    let mut cursor = Cursor::new(tx_bytes);
    let tx = Transaction::read(&mut cursor, branch_id).ok()?;
    // A single well-formed transaction consumes its whole slice. Block tx
    // segments are exact (the block parser delimits each tx), so a leftover tail
    // means malformed input -- reject rather than short_id a partial parse.
    if cursor.position() as usize != tx_bytes.len() {
        return None;
    }
    // Only v5 (ZIP-244) transactions carry an auth digest; pre-v5 has none, so
    // the sidecar cannot resolve them either -- leave them prefilled.
    if !matches!(tx.version(), TxVersion::V5) {
        return None;
    }
    // Both values are internal (wire) byte order; store them as-is (no reversal).
    let txid_wire: [u8; 32] = *tx.txid().as_ref();
    let auth_wire: [u8; 32] = tx.auth_commitment().as_bytes().try_into().ok()?;
    Some(WtxId::new(
        TxId::from_bytes(txid_wire),
        AuthDigest::from_bytes(auth_wire),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovright_relay_sidecar::mempool_sync::wtxid_from_display_hex;

    // Real ZIP-244 test vector: the first vector of librustzcash's
    // `zcash_primitives` `zip_0244` test data, itself generated from
    // zcash/zcash-test-vectors `zip_0244.py`. It is a NU5 v5 transaction.
    //
    // `*_WIRE_HEX` are the vector's `txid`/`auth_digest` fields verbatim --
    // internal (wire) byte order, i.e. exactly what `tx.txid().as_ref()` and
    // `tx.auth_commitment().as_ref()` return (asserted by librustzcash's own
    // `zip_0244` test). `*_DISPLAY_HEX` are those bytes reversed, i.e. what
    // Zebra's RPC would report and what the sidecar's `wtxid_from_display_hex`
    // consumes.
    const VECTOR_TXID_DISPLAY_HEX: &str =
        "d0854b7070bb168392e7cf3d3a558711b49c2c0ad8eca3a8a14b8333bd962c55";
    const VECTOR_AUTH_DISPLAY_HEX: &str =
        "57dcab20681fee70a3c653b66322fe3f6158f89ccba1b30f366785675f7e7612";
    const VECTOR_TXID_WIRE_HEX: &str =
        "552c96bd33834ba1a8a3ecd80a2c9cb41187553a3dcfe7928316bb70704b85d0";
    const VECTOR_AUTH_WIRE_HEX: &str =
        "12767e5f678567360fb3a1cb9cf858613ffe2263b653c6a370ee1f6820abdc57";
    const VECTOR_V5_TX_HEX: &str = "050000800a27a726b4d0d6c27a8f739a2d6f2c0201e152a8049e294c4d6e66b164939daffa2ef6ee6921481cdd86b3cc4318d9614fc820905d0453516aaca3f2498800019f33bf3a109bdd1b232b47b1646d91e1296634ebde5ccad57288b5b2228186e54b6968912a6381ce3dc166d56a1d62f5a8d7551db5fd9313e8c7203d996af7d41a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f25c9a138f49b1a5301466b3da612149df5eda0f14f2efc5c6ac03884428a315dc91f8d7b492ebc57e475a4a6f26572504b192232ecb9f0c02411e52596bc5e90457e745939ffedbd121e37ec1e9dddc31b06dc9576a1738ef73e6ba71648913dbf75a779fdd488d83f857deecc40a98d5f2935395ee4762dd21afdbb5d47fa9a6dd984d567db2857b927b7fae2db587105415d4642789d38f50b8dbcc129cab3d17d19f3355bcf73cecb8cb8a5da01307152f13936a270572670dc82d39026c6cb4cd4b0f7f5aa2a4f5a5341ec5dd715406f2fdd2afa733f5f641c8c21862a1bafce2609d9eecfa158cfb5cd79f88008e315dc7d8388e76c1782fd2795d18a763624c25fa959cc97489ce75745824b77868c53239cfbdf73caec65604037314faaceb56218c6bd30f8374ac13386793f21a9fb80ad03bc0cda4a44946c00e1b1a1df0e5b87b5bece477a709649e950060591394812951e1fe3895b8cc3d14d2cf6556df6ed4b4ddd3d9a69f53357d7767f4f5ccbdbc596631277f8fecd08cb056b95e3025b9792fff7f244fc716269b926d62e9596fa825c6bf21aff9e68625a192440ea06828123d97884806f15fa08da52754a1095e3ff1abd5ce4fddfccfc3a6128aef784a64610a89d1a7099216d0814d3a2d452431c32d411ac1cce82ad0229407bbc48985675e3f874a4533f1d63a84dfa3e0f460fe2f57e34fbc75423c3737f5b2a0615f5722db041a3ef66fa483afd3c2e19e59444a64add6df1d963f5dd5b5010d3d025f0287c4cf19c75f33d51ddddba5d657b43ee8da645443814cc7329f3e9b4e54c236c29af3923101756d9fa4bd0f7d2ddaacb6b0f86a2658e0a07a05ac5b950051cd24c47a88d13d659ba2a46ca1830816d09cd7646f76f716abec5de07fe9b523410806ea6f288f8736c23357c85f45791e1708029d9824d90704607f387a03e49bf9836574431345a7877efaa8a08e73081ef8d62cb780ab6883a50a0d470190dfba10a857f82842d3825b3d6da0573d316eb160dc0b716c48fbd467f75b780149ae8808f4e68f50c0536acddf6f1aeab016b6bc1a51ed44cfab70000c7b3534201cfb1cd8dbf69b8250c18ef41294ca97993db546c1fe01f7e9c8e367edcf04be34a9851a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da948d320dadd64f5431e61ddf658d24ae67c22c8d1309131fc00fe7f235734276d38d47f1e191e00c7a1d48af046827591e9733a97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878f73476f21a482ec9378365c8f7393c94e2885315eb4671098b79535e790fe53e29fef2b3766697ac32b4f473f468a008e72389fc03880d780cb07fcfaabe3f1a84b27db59a4a153d1070689f2ccf975b2b176e1c69dbe381340ef1f98fdc4b453abda3a2bfac3069ba7f1cc50a81c2520e412fab4e5d397ecf739f280d5b684533d5d29cfe7e7302ec144b4e553acfd670f77e755fc88e0677e31ba459b44e307768958fe3789d41c2b1ff434cb30e15914f01bc6bc2307b488d2556d7b7380ea4ffd712f6b02fe806b94569cd4059f396bf29b99d0a40e5e1711ca944f72d436a102fca4b97693da0b086fe9d2e7162470d02e0f05d4bec9512bfb3f38327296efaa74328b118c27402c70c3a90b49ad4bbc68e37c0aa7d9b3fe17799d73b841e751713a02943905aae0803fd69442eb7681ec2a05600054e92eed555028f21b6a155268a2dd664052528a5f8ed028f59af985ad1315c2e25aeb9d7f134e4bf478642ab96b15d3b3e13ce2387ac84dc0819e81260e11d392a5f06db8b5633de281a0e9c958c24060297f608af1dc51616562b1ffff6e2a28bab1f7772713a0a4b56fe47fb5a7b73aeee5345566ecf3e95e825f92eb469eb5d69164206a0ea1ce73bfb2a942e73703214d270d80534389b1a1e2bba67481eb3667d6d38254ac4b44559b4708cdd12898972a895bf0fb055cf1fb9b73029d6bfb27da2b5294f5cb354a894322848cc3d35b9554a5f62b44a7dcb25406e5ba07882cb6473714e77a051a7dcd29fea0a943785b325cdab95404fc7aed70525cddb41872cfcc214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edcedc6a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe65951e610620f71cda8fc877625f2c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d3249abb1342bb0eebf62058bf3de080d94611a3750915b5dc6c0b3899d41222bace760ee9c8818ded599e34c56d7372af1eb86852f2a732104bdb750739de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff59158bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797563a26b1d61fcd9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5e1289be1b2004caca8d3f34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e319094318cd405ba27b7e2c084762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e98082ea5ce9534b3acd60fe49e37e4f666931677319ed89f85588741b3128901a93bd78e4be0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de6ba6bf4490adfe7444cd467a09075417fcc0062e49f008c51ad4227439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22ee273e15786e394c8f1be31682a30147963ac8da8d41d804258426a3f70289b8ad19d8de13be4eebe3bd4c8a6f55d6e0c373d456851879f5fbc282db9e134806bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141ee120fdc34d6764eafc66880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35cd8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d325b440f6b9f59aff66879bb6688fdb462af43582b983f92b5698b87db46e4b02dd8e81eca555a44f2f1aef11d88a0bcee76af9ad3f9c46a67062e1a9ca7ea5c014384af07219c7c0ee7fc7bfc7933d174650f46b4cc000190c19b44c57ae891aa86646c10a177a8626be064409931c37d9e8bdc433b7d79e08a12f738a8f0dbddfef2f2657ef3e47d1b0fd11e6a13654db2854fcbff49aa0dadafec320b6ed2d4b279aee9060c1b221e2eb2f13b0691c4d842406d0ec4282c9526174a09878fe8fdde33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa371046613260cf3354cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737a4c447586f69173446d8e48bf84cbc000a807899973eb93c5e819aad669413f8387933ad1584aa35e43f4ecd1e2d0407c0b1b89920ffdfdb9bea51ac95b557af71b89f903f5d9848f14fcbeb1837570f544d6359eb23faf38a0822da36ce426c4a2fbeffeb0a8a2e297a9d19ba15024590e3329d9fa9261f9938a4032dd34606c9cf9f3dd33e576f05cd1dd6811c6298757d77d9e810abdb226afcaa4346a6560f8932b3181fd355d5d391976183f8d99388839632d6354f666d09d3e5629ea19737388613d38a34fd0f6e50ee5a0cc9677177f50028c141378187bd2819403fc534f80076e9380cb4964d3b6b45819d3b8e9caf54f051852d671bf8c1ffde2d1510756418cb4810936aa57e6965d6fb656a760b7f19adf96c173488552193b147ee58858033dac7cd0eb204c06490bbdedf5f7571acb2ebe76acef3f2a01ee987486dfe6c3f0a5e234c127258f97a28fb5d164a8176be946b8097d0e317287f33bf9c16f9a545409ce29b1f4273725fc0df02a04ebae178b3414fb0a82d50deb09fcf4e6ee9d180ff4f56ff3bc1d3601fc2dc90d814c3256f4967d3a8d64c83fea339c51f5a8e5801fbb97835581b602465dee04b5922c2761b54245bec0c9eef2db97d22b2b3556cc969fbb13d06509765a52b3fac54b93f421bf08e18d52ddd52cc1c8ca8adfaccab7e5cc2f4573fbbf8239bb0b8aedbf8dad16282da5c9125dba1c059d0df8abf621078f02d6c4bc86d40845ac1d59710c45f07d585eb48b32fc0167ba256e73ca3b9311c62d1094903570519d4442f0200e6ad11f2452dc9ae85aec01fc56f8cbfda75a7727b75ebbd6bbffb43b63a3b1b871e40feb0db002974a3c3b1a788567231bf6399ff89236981149d423802d2341a3bedb9ddcbac1fe7b6435e1479c72e7089d029e7fbbaf3cf37e9b9a6b776791e4c5e6fda57e8d5f14c8c35a2d270846b9dbe005cda16af4408f3ab06a916eeeb9c9594b70424a4c1d171295b6763b22f47f80b53ccbb904bd68fd65fbd3fbdea1035e98c21a7dba5fe1089f7d1c032f24d36835aa8815266e897ff829403cfac3a715954b9b68958a0111a2c9265633ba2831a2e86b941e569d58d99c1383597fad81193c4c13151f40aedb487b5c04ae3b1ddfbafa26e720099f26d5a7535aee57306fd2c4f30673cd9b698fecf32faf88f62e21c90665859dd26833d21d9bc5452bd19515d3fa5c1e68bc209b9dc2a10ae6b630726a67b33603c691fafc281dd94dc9888a68c4f45155aa7897c045aafd9335be2e0ddcf5f586d7f6b4fe12dad9a17f5db7031";

    fn wtxid_from_hex_vector() -> WtxId {
        let tx_bytes = hex::decode(VECTOR_V5_TX_HEX).unwrap();
        wtxid_from_tx_bytes(&tx_bytes, BranchId::Nu5).expect("real v5 vector must resolve")
    }

    /// The load-bearing proof: the from-bytes path equals the sidecar's
    /// from-Zebra-display path, byte-for-byte, for a real ZIP-244 transaction.
    /// If either the txid or the auth digest were reversed, this fails.
    #[test]
    fn from_bytes_equals_sidecar_from_display_for_zip244_vector() {
        let actual = wtxid_from_hex_vector();
        let sidecar = wtxid_from_display_hex(VECTOR_TXID_DISPLAY_HEX, VECTOR_AUTH_DISPLAY_HEX)
            .expect("sidecar must parse display hex");
        assert_eq!(
            actual, sidecar,
            "from-bytes wtxid must match the sidecar's from-display wtxid"
        );
    }

    /// Independent cross-check of the same claim, pinning the exact 64 wire
    /// bytes: `to_bytes()` = wire txid (32) || wire auth digest (32).
    #[test]
    fn from_bytes_produces_expected_wire_layout() {
        let wtxid = wtxid_from_hex_vector();
        let bytes = wtxid.to_bytes();
        assert_eq!(hex::encode(&bytes[..32]), VECTOR_TXID_WIRE_HEX);
        assert_eq!(hex::encode(&bytes[32..]), VECTOR_AUTH_WIRE_HEX);
    }

    /// Proves the `branch_id` argument is ignored for v5: the same transaction
    /// yields the same wtxid whatever branch id we pass, because v5 self-encodes
    /// its consensus branch id and the txid/auth digest bind that embedded value.
    #[test]
    fn branch_id_argument_is_ignored_for_v5() {
        let tx_bytes = hex::decode(VECTOR_V5_TX_HEX).unwrap();
        let with_nu5 = wtxid_from_tx_bytes(&tx_bytes, BranchId::Nu5);
        let with_nu6 = wtxid_from_tx_bytes(&tx_bytes, BranchId::Nu6);
        let with_nu6_2 = wtxid_from_tx_bytes(&tx_bytes, BranchId::Nu6_2);
        assert!(with_nu5.is_some());
        assert_eq!(with_nu5, with_nu6);
        assert_eq!(with_nu5, with_nu6_2);
    }

    /// A real pre-v5 (Sapling v4) transaction has no auth digest, so it must
    /// return `None` (left prefilled), matching the sidecar mempool sync.
    #[test]
    fn pre_v5_transaction_returns_none() {
        const V4_TX_HEX: &str = "0400008085202f89018f642996df1e93a6d79ae5baae3493f423ca6c82e99f3e8d9524fa78bcf16167000000006b483045022100b65e37229707d9cd483940d2ab8bdc0b74b12dda66d02dbdf36fd383b9602a5102204be7fd7a39a4a42dff071a5a2bc51b492d33f0bc394bc87861e1bcaaf2bac93b01210248e78bdc18f1a83110c12e4008b764026961b168fe8d5a8d947efe6af83cc88effffffff01f0f27018020000001976a914a284d0511d0e520d36f444a36c10bf54b4b017cd88ac00000000d7450400000000000000000000000100ca9a3b0000000000000000000000001331a3059e66aa6ca97a62f56ea234207568566f6971b3722ae0dd82c00399692aacb5fb12ac580ac26624a8cf0a904cd6f4bfea55625205cb58f06b1c197423280deac74eea97598c4314d899a4fd85311e046257d2d4c297f1406cf709d92a8607f7698d45fe9f41dea3a0571c5da5cfa78e18ebf580c36179d9d6e6320a348f146c407adab4cb310392a5f5b5ab283b78343ba91abc7c4bfe23a3dbaf8037c676e595a26574b1813bc2bf2d2e911f6f3abb0ba6bcac7a2901fbdce65fb07b5636017ef14dff44cdeea730477294f2f8619bd3d5e6be4898bf8d39c0e0eae5a36864625206b9a8f9940bf16650def7926eb0db43b7d7615e4774cf109482f2e807fee6c0c884e8314c67c5d85f4c229cdeab1e964cf0c1adcb47cebfc7c067a0f3c806814a285edbb624f4710629098944ac75e7c9cbc56bd0a029e1110eac60cb4077ebf108fe3e67cd061391e5d6916d5f41c02b8914c12cf605db7d959226e2e8ff71263b9af4c59b0f4db315b74ca2b0b7d25213d5293954c3e51172370fb6c35abe9ce36ef253e3a72e19dac9bd7362c44992974215c82cb90c99488dbde11963e857cea6b81b8eaae34b7cf5a97d6b60d49fdfa20f5f3c120ef382ca2469604fb0c6842c6d4fae9661665b5cbc612cef132f88fb7da393f356e3ad13fc3557980a7734231453e44079042fb432f55e751484d5d6d30fbc4f999013d5d4f2fb62f7144e8dcd2ae59546cc4379ad9f1859ef80dec66b1a9b0b7fd2c47bd38302d29c31990329a895876ed1d84db757856e75ce9a1dc7c7472bc218fb8d7c7d028bb02f10efe7fe6a8c9ce034fea66b909c8d4126251c7d6e54f4cfc778cd4f0e0bad1096176f2dd45c45cbe15e118f90ff2545f832f23698f2c9531b52655a4c0c8953559928eedfc756c365cf929b8447dcdc7d823849e02ff68b6278d7542ce0f1070bb1ad913c1a353625f5d35b14cfec84a633d7fe25256dcffe92f9a6f0fe00caaaa5b39cc2ab06768a42a5b40083cea01c96b3e68d0f6a587eaf2da6fdadc82527f186a60471ce98e27d2b11efc47998f3030a7a2e5d0b0a7eb80f6bd0e4b9c8367c6c522d9415f8caec7b0a7318d53dce391cf7e7389c9a74aa6a4c217c288519af81ba2122ca0c5840cc02cf1bcf150cd3df33c0acfd0053e668b926561b924098d97aaab57ee1113df966a422ef9b014617bceef05fb6468e330e2dece3f375e98ef03e5b18a953e2301fccec86200ae432c9c12c30775437f3629714a9fabeb53289402b7fd386cef2b1146723a89d0f81651e00caea2f3ac9eefefb868d85ed2354f530fe38fe3a3a6aab47d42dc21329e3ad1b9d06c0c8d6537456f54ad0453f444175d87ef5cdd1694662e0a1e6e3632ed7a8e76bc7b1b5a418f086d340815ec398f092e97869f5e201c22c87918f766a3532eb9a4fc9acf196cbc2d0285119a4216d2581cd2d91bcdce868c468f6f34cf49e3a56ce249a2fd8cf36b01b0f77de722bbce267e3e5521688e65222235c91c263d80e28297e929d885b7b9c1a1654b2d0b87577c9a1c725f54415dc5f52dde0695f9f6dcb4b6ee3e3ea702904c11ff92f55534c7ef98ce793d74756a45d4e320a425e982d5b372d6a8d41fb86ba5164816832a481825c8c6ad7270969859e55d2367535060f99857065170466bdb70cb93ab2f9c0e293a0a919843bbf34c2fe61b0c3e32aa7078e83d4c1929e1e1d86141cdeb18920910975db3a7626820599630c423ade233d5d60685524e8d8032b861b4aad2002a8fd17c9282b825f02d353e291379ced00ebaa3c03e01d9c59f405099d1c3432bad06358d6b1942f0baf710998d10a22d155b0fe849952893126949ff92de3a4c2eeafdf688435e325d81c2ce008cf6c76030d4d46342ac3372c73986560c4ec35a6f649ef02c11936b7039bc6f5d09438dbe476251b5964b68f02eedff7a9e0ed3e3090965a22f2c552ce3b2b474fd2fc06b50927830a05a303faffd68482d7b78538432540dd3261ab759b6582129a7f18d801c54319ca52a3c6a3db635044d625e24038ad4277f8d5bf016035165f21b070e8169d657d6ed1fa7f8ed09b4e1d9ca2e51a24da55e43b3fca9859b2408c26aacbad749ebe882c31e7205e638bb7e2bfc8a3f1c02c0ca7bb9daaab7fcbf845d8002c3de79924dcaadc24bdc0082f4a6b61876f3192a881f59a682d273685d4795c9bd7cccf49de34443a9f9cb35bbf254c50611b7c1324b11094667b6b608c39d1252cebcc4877ceea76e19b842b67f626743fab297776cc9cf79e90e8fce1001790c2e7d5c958647cca5d3397d20afcf29ba44f62a7c62e908d848d81a79fadbb370aba93b03e41d4bc49e299d6d33faf869f36371414ce646fc2ca6dcff55a6e0639d50caeb114c418c626b86715436481d1928d55a756a603e7110c3afe963c2b29a478f9d4397b885a67b093a345796219c111b7e94db390aa4bb76b66a534e5e2679b27db5f95fd09a36b05";
        let tx_bytes = hex::decode(V4_TX_HEX).unwrap();
        assert_eq!(wtxid_from_tx_bytes(&tx_bytes, BranchId::Sapling), None);
        assert_eq!(
            wtxid_from_tx_bytes(&tx_bytes, SOVRIGHT_P2P_CONSENSUS_BRANCH_ID),
            None
        );
    }

    #[test]
    fn malformed_input_returns_none_without_panicking() {
        assert_eq!(wtxid_from_tx_bytes(&[], BranchId::Nu5), None);
        assert_eq!(wtxid_from_tx_bytes(&[0x00], BranchId::Nu5), None);
        assert_eq!(wtxid_from_tx_bytes(&[0xff; 16], BranchId::Nu5), None);
        // A v5 header followed by garbage: parse must fail cleanly.
        assert_eq!(
            wtxid_from_tx_bytes(&[0x05, 0x00, 0x00, 0x80, 0xde, 0xad], BranchId::Nu5),
            None
        );
    }

    #[test]
    fn trailing_bytes_after_a_valid_tx_returns_none() {
        let mut tx_bytes = hex::decode(VECTOR_V5_TX_HEX).unwrap();
        // Sanity: the exact bytes resolve.
        assert!(wtxid_from_tx_bytes(&tx_bytes, BranchId::Nu5).is_some());
        // One extra trailing byte must be rejected (not a partial parse).
        tx_bytes.push(0x00);
        assert_eq!(wtxid_from_tx_bytes(&tx_bytes, BranchId::Nu5), None);
    }

    #[test]
    fn truncated_v5_tx_returns_none() {
        let tx_bytes = hex::decode(VECTOR_V5_TX_HEX).unwrap();
        let half = &tx_bytes[..tx_bytes.len() / 2];
        assert_eq!(wtxid_from_tx_bytes(half, BranchId::Nu5), None);
    }
}
