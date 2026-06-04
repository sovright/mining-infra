use tokio_util::codec::LinesCodec;

#[derive(Debug, Clone, Copy, Default)]
pub struct V1Codec;

impl V1Codec {
    pub const MAX_LINE_LENGTH: usize = 1024 * 1024;

    pub fn new() -> LinesCodec {
        LinesCodec::new_with_max_length(Self::MAX_LINE_LENGTH)
    }
}
