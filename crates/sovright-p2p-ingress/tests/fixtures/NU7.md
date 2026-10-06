# NU7 activation fixture

`testnet_nu7_4465026.hex` is the unmodified public-testnet activation block.
Its metadata freezes the consensus block hash, raw-byte SHA-256, transaction
sizes, and `getblock` verbosity-2 txid/authdigest results from both pinned clients.
The raw block was also retrieved by public P2P `getdata`; its SHA-256 matches the
bytes accepted by Zebra in the earlier controlled activation replay. Public
fixture provenance contains no private host inventory or operational endpoints.

The block contains a v6 coinbase with one Ironwood action and a non-coinbase v5
transaction. Tests compare each transaction's digest against both node oracles
and reconstruct the exact raw bytes through all-prefilled, cached compact and
skeleton paths. Missing receiver cache data must first report incomplete.

The v6 coinbase remains prefilled: short-ID resolution here exercises only the
v5 transaction. This is not general shielded-transaction, relay transport,
FEC/recovery, or submission-path qualification. The two clients share code
ancestry; matching RPC digests are not independent cryptographic implementations.
