use tokio_util::codec::LinesCodec;

#[derive(Debug, Clone, Copy, Default)]
pub struct V1Codec;

impl V1Codec {
    pub const MAX_LINE_LENGTH: usize = 1024 * 1024;

    // `V1Codec` is a zero-sized config holder; `new()` is a factory that
    // builds the underlying `tokio_util` `LinesCodec` with our max line length.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> LinesCodec {
        LinesCodec::new_with_max_length(Self::MAX_LINE_LENGTH)
    }
}
