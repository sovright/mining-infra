use std::net::SocketAddr;

use sovright_relay::{TxFeedRecord, WtxId};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct TxFeedClient {
    addr: SocketAddr,
}

impl TxFeedClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn send(&self, wtxid: WtxId, tx_bytes: &[u8]) -> Result<()> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream
            .write_all(TxFeedRecord::encode_line(wtxid, tx_bytes).as_bytes())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovright_relay::{AuthDigest, TxId, WtxId};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[tokio::test]
    async fn tx_feed_client_writes_sidecar_line_format() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).await.unwrap();
            line
        });
        let client = TxFeedClient::new(addr);
        let wtxid = make_wtxid(0x31);
        let tx = vec![0xde, 0xad, 0xbe, 0xef];

        client.send(wtxid, &tx).await.unwrap();

        assert_eq!(server.await.unwrap(), TxFeedRecord::encode_line(wtxid, &tx));
    }
}
