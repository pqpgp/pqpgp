//! Benchmarks for post-quantum cryptographic operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pqpgp::crypto::{decrypt_message, encrypt_message, sign_message, verify_signature, KeyPair};
use rand::rngs::OsRng;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");
    let mut rng = OsRng;

    group.bench_function("mlkem1024", |b| {
        b.iter(|| KeyPair::generate_mlkem1024(&mut rng))
    });

    group.bench_function("mldsa87", |b| {
        b.iter(|| KeyPair::generate_mldsa87(&mut rng))
    });

    group.finish();
}

fn bench_hybrid_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid_operations");
    let mut rng = OsRng;

    group.bench_function("generate_hybrid", |b| {
        b.iter(|| KeyPair::generate_hybrid(&mut rng))
    });

    group.finish();
}

fn bench_encryption_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption_operations");
    let mut rng = OsRng;

    // Pre-generate key pairs for consistent benchmarking
    let mlkem_keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();
    let (hybrid_enc_keypair, _hybrid_sig_keypair) = KeyPair::generate_hybrid(&mut rng).unwrap();

    // Test different message sizes
    let small_msg = vec![0u8; 64]; // 64 bytes
    let medium_msg = vec![0u8; 1024]; // 1KB
    let large_msg = vec![0u8; 64 * 1024]; // 64KB

    // ML-KEM-1024 encryption benchmarks
    group.throughput(Throughput::Bytes(64));
    group.bench_function("mlkem1024_encrypt_64b", |b| {
        b.iter(|| {
            encrypt_message(
                black_box(mlkem_keypair.public_key()),
                black_box(&small_msg),
                black_box(&mut rng),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("mlkem1024_encrypt_1kb", |b| {
        b.iter(|| {
            encrypt_message(
                black_box(mlkem_keypair.public_key()),
                black_box(&medium_msg),
                black_box(&mut rng),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("mlkem1024_encrypt_64kb", |b| {
        b.iter(|| {
            encrypt_message(
                black_box(mlkem_keypair.public_key()),
                black_box(&large_msg),
                black_box(&mut rng),
            )
        })
    });

    // Hybrid encryption benchmarks (using encryption keypair)
    group.throughput(Throughput::Bytes(64));
    group.bench_function("hybrid_encrypt_64b", |b| {
        b.iter(|| {
            encrypt_message(
                black_box(hybrid_enc_keypair.public_key()),
                black_box(&small_msg),
                black_box(&mut rng),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hybrid_encrypt_1kb", |b| {
        b.iter(|| {
            encrypt_message(
                black_box(hybrid_enc_keypair.public_key()),
                black_box(&medium_msg),
                black_box(&mut rng),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("hybrid_encrypt_64kb", |b| {
        b.iter(|| {
            encrypt_message(
                black_box(hybrid_enc_keypair.public_key()),
                black_box(&large_msg),
                black_box(&mut rng),
            )
        })
    });

    group.finish();
}

fn bench_decryption_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("decryption_operations");
    let mut rng = OsRng;

    // Pre-generate key pairs and encrypted messages for consistent benchmarking
    let mlkem_keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();
    let (hybrid_enc_keypair, _hybrid_sig_keypair) = KeyPair::generate_hybrid(&mut rng).unwrap();

    let small_msg = vec![0u8; 64];
    let medium_msg = vec![0u8; 1024];
    let large_msg = vec![0u8; 64 * 1024];

    let mlkem_encrypted_small =
        encrypt_message(mlkem_keypair.public_key(), &small_msg, &mut rng).unwrap();
    let mlkem_encrypted_medium =
        encrypt_message(mlkem_keypair.public_key(), &medium_msg, &mut rng).unwrap();
    let mlkem_encrypted_large =
        encrypt_message(mlkem_keypair.public_key(), &large_msg, &mut rng).unwrap();

    let hybrid_encrypted_small =
        encrypt_message(hybrid_enc_keypair.public_key(), &small_msg, &mut rng).unwrap();
    let hybrid_encrypted_medium =
        encrypt_message(hybrid_enc_keypair.public_key(), &medium_msg, &mut rng).unwrap();
    let hybrid_encrypted_large =
        encrypt_message(hybrid_enc_keypair.public_key(), &large_msg, &mut rng).unwrap();

    // ML-KEM-1024 decryption benchmarks
    group.throughput(Throughput::Bytes(64));
    group.bench_function("mlkem1024_decrypt_64b", |b| {
        b.iter(|| {
            decrypt_message(
                black_box(mlkem_keypair.private_key()),
                black_box(&mlkem_encrypted_small),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("mlkem1024_decrypt_1kb", |b| {
        b.iter(|| {
            decrypt_message(
                black_box(mlkem_keypair.private_key()),
                black_box(&mlkem_encrypted_medium),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("mlkem1024_decrypt_64kb", |b| {
        b.iter(|| {
            decrypt_message(
                black_box(mlkem_keypair.private_key()),
                black_box(&mlkem_encrypted_large),
                black_box(None),
            )
        })
    });

    // Hybrid decryption benchmarks (using encryption keypair)
    group.throughput(Throughput::Bytes(64));
    group.bench_function("hybrid_decrypt_64b", |b| {
        b.iter(|| {
            decrypt_message(
                black_box(hybrid_enc_keypair.private_key()),
                black_box(&hybrid_encrypted_small),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hybrid_decrypt_1kb", |b| {
        b.iter(|| {
            decrypt_message(
                black_box(hybrid_enc_keypair.private_key()),
                black_box(&hybrid_encrypted_medium),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("hybrid_decrypt_64kb", |b| {
        b.iter(|| {
            decrypt_message(
                black_box(hybrid_enc_keypair.private_key()),
                black_box(&hybrid_encrypted_large),
                black_box(None),
            )
        })
    });

    group.finish();
}

fn bench_signature_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_operations");
    let mut rng = OsRng;

    // Pre-generate key pairs for consistent benchmarking
    let mldsa_keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();
    let (_hybrid_enc_keypair, hybrid_sig_keypair) = KeyPair::generate_hybrid(&mut rng).unwrap();

    // Test different message sizes
    let small_msg = vec![0u8; 64];
    let medium_msg = vec![0u8; 1024];
    let large_msg = vec![0u8; 64 * 1024];

    // ML-DSA-87 signing benchmarks
    group.throughput(Throughput::Bytes(64));
    group.bench_function("mldsa87_sign_64b", |b| {
        b.iter(|| {
            sign_message(
                black_box(mldsa_keypair.private_key()),
                black_box(&small_msg),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("mldsa87_sign_1kb", |b| {
        b.iter(|| {
            sign_message(
                black_box(mldsa_keypair.private_key()),
                black_box(&medium_msg),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("mldsa87_sign_64kb", |b| {
        b.iter(|| {
            sign_message(
                black_box(mldsa_keypair.private_key()),
                black_box(&large_msg),
                black_box(None),
            )
        })
    });

    // Hybrid signing benchmarks (using signing keypair)
    group.throughput(Throughput::Bytes(64));
    group.bench_function("hybrid_sign_64b", |b| {
        b.iter(|| {
            sign_message(
                black_box(hybrid_sig_keypair.private_key()),
                black_box(&small_msg),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hybrid_sign_1kb", |b| {
        b.iter(|| {
            sign_message(
                black_box(hybrid_sig_keypair.private_key()),
                black_box(&medium_msg),
                black_box(None),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("hybrid_sign_64kb", |b| {
        b.iter(|| {
            sign_message(
                black_box(hybrid_sig_keypair.private_key()),
                black_box(&large_msg),
                black_box(None),
            )
        })
    });

    group.finish();
}

fn bench_verification_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_operations");
    let mut rng = OsRng;

    // Pre-generate key pairs and signatures for consistent benchmarking
    let mldsa_keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();
    let (_hybrid_enc_keypair, hybrid_sig_keypair) = KeyPair::generate_hybrid(&mut rng).unwrap();

    let small_msg = vec![0u8; 64];
    let medium_msg = vec![0u8; 1024];
    let large_msg = vec![0u8; 64 * 1024];

    let mldsa_sig_small = sign_message(mldsa_keypair.private_key(), &small_msg, None).unwrap();
    let mldsa_sig_medium = sign_message(mldsa_keypair.private_key(), &medium_msg, None).unwrap();
    let mldsa_sig_large = sign_message(mldsa_keypair.private_key(), &large_msg, None).unwrap();

    let hybrid_sig_small =
        sign_message(hybrid_sig_keypair.private_key(), &small_msg, None).unwrap();
    let hybrid_sig_medium =
        sign_message(hybrid_sig_keypair.private_key(), &medium_msg, None).unwrap();
    let hybrid_sig_large =
        sign_message(hybrid_sig_keypair.private_key(), &large_msg, None).unwrap();

    // ML-DSA-87 verification benchmarks
    group.throughput(Throughput::Bytes(64));
    group.bench_function("mldsa87_verify_64b", |b| {
        b.iter(|| {
            verify_signature(
                black_box(mldsa_keypair.public_key()),
                black_box(&small_msg),
                black_box(&mldsa_sig_small),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("mldsa87_verify_1kb", |b| {
        b.iter(|| {
            verify_signature(
                black_box(mldsa_keypair.public_key()),
                black_box(&medium_msg),
                black_box(&mldsa_sig_medium),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("mldsa87_verify_64kb", |b| {
        b.iter(|| {
            verify_signature(
                black_box(mldsa_keypair.public_key()),
                black_box(&large_msg),
                black_box(&mldsa_sig_large),
            )
        })
    });

    // Hybrid verification benchmarks (using signing keypair)
    group.throughput(Throughput::Bytes(64));
    group.bench_function("hybrid_verify_64b", |b| {
        b.iter(|| {
            verify_signature(
                black_box(hybrid_sig_keypair.public_key()),
                black_box(&small_msg),
                black_box(&hybrid_sig_small),
            )
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hybrid_verify_1kb", |b| {
        b.iter(|| {
            verify_signature(
                black_box(hybrid_sig_keypair.public_key()),
                black_box(&medium_msg),
                black_box(&hybrid_sig_medium),
            )
        })
    });

    group.throughput(Throughput::Bytes(64 * 1024));
    group.bench_function("hybrid_verify_64kb", |b| {
        b.iter(|| {
            verify_signature(
                black_box(hybrid_sig_keypair.public_key()),
                black_box(&large_msg),
                black_box(&hybrid_sig_large),
            )
        })
    });

    group.finish();
}

fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");
    let mut rng = OsRng;

    // Pre-generate key pairs for batch operations
    let (enc_keypair, sig_keypair) = KeyPair::generate_hybrid(&mut rng).unwrap();
    let message = vec![0u8; 1024];

    // Batch encryption
    group.bench_with_input(BenchmarkId::new("batch_encrypt", 10), &10, |b, &count| {
        b.iter(|| {
            for _ in 0..count {
                let _ = encrypt_message(
                    black_box(enc_keypair.public_key()),
                    black_box(&message),
                    black_box(&mut rng),
                );
            }
        })
    });

    // Batch signing
    group.bench_with_input(BenchmarkId::new("batch_sign", 10), &10, |b, &count| {
        b.iter(|| {
            for _ in 0..count {
                let _ = sign_message(
                    black_box(sig_keypair.private_key()),
                    black_box(&message),
                    black_box(None),
                );
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_hybrid_operations,
    bench_encryption_operations,
    bench_decryption_operations,
    bench_signature_operations,
    bench_verification_operations,
    bench_batch_operations
);
criterion_main!(benches);
