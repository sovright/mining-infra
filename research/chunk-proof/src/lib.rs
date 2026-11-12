//! Research prototype for #130 PR B, the chunk layer. The bound raw path in `sovright-relay`
//! uses it, behind switches that are off by default. Chunk version 4 is a candidate, and a
//! different carrier would change [`datagram`] and nothing else.
//!
//! What each stage shows, and what it does not:
//!
//! | Stage                         | Shows                              | Does not show        |
//! |-------------------------------|------------------------------------|----------------------|
//! | One chunk, A1 to A4           | This shard, at this index and      | That the root is     |
//! |                               | shape, is a leaf under `object_id` | canonical            |
//! | `k` chunks in                 | Those `k` leaves are under it      | That they decode to  |
//! |                               |                                    | a codeword           |
//! | D1 to D4 passed               | Every leaf, parity and padding is  | That any parser will |
//! |                               | the canonical encoding of `content`| accept `content`     |
//!
//! A sender with the session key can build a tree of its own over any bytes. Such a tree
//! passes A1 to A4 under its own root, and only the decode can tell. What a chunk cannot do
//! is take a slot under a root it does not belong to, and that is the point.
//!
//! No chunk touches a slot or a rejected record before A1 to A4 have passed, because
//! [`datagram::VerifiedChunk`] is the only thing [`assembler::Assembler`] stores from.
//!
//! A decode is not a delivery. [`handoff`] takes a decoded object to the segment
//! prototype, and what happens to it after that is the segment ledger's to say.

pub mod assembler;
pub mod budget;
pub mod datagram;
pub mod gate;
pub mod handoff;
pub mod object;
pub mod tree;
