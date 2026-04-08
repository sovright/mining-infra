use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use bedrock_noise::handshake::{NoiseInitiator, NoiseResponder};
use bedrock_noise::keys::Keypair;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

/// Set up a Noise-encrypted client/server pair over localhost TCP.
async fn make_noise_pair() -> (
    bedrock_noise::NoiseStream<TcpStream>,
    bedrock_noise::NoiseStream<TcpStream>,
) {
    let server_keypair = Keypair::generate();
    let server_public = server_keypair.public.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let responder = NoiseResponder::new(server_keypair);
        responder.accept(stream).await.unwrap()
    });

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let initiator = NoiseInitiator::new(server_public);
    let client = initiator.connect(client_stream).await.unwrap();
    let server = server_handle.await.unwrap();

    (client, server)
}

fn bench_noise_transport(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("noise_transport");

    for size in [100, 10_000] {
        let payload = vec![0xABu8; size];

        group.bench_with_input(
            BenchmarkId::new("roundtrip", size),
            &payload,
            |b, payload| {
                b.iter(|| {
                    rt.block_on(async {
                        let (mut client, mut server) = make_noise_pair().await;

                        // Client writes, server reads
                        client.write_message(black_box(payload)).await.unwrap();
                        let received = server.read_message().await.unwrap();
                        assert_eq!(received.len(), payload.len());

                        // Server writes back, client reads
                        server.write_message(black_box(&received)).await.unwrap();
                        let echoed = client.read_message().await.unwrap();
                        assert_eq!(echoed.len(), payload.len());
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_noise_transport);
criterion_main!(benches);
