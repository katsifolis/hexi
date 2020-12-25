use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hexi::{get_data_repr, Repr};
use rand;

fn criterion_benchmark(c: &mut Criterion) {
    let mut vec: Vec<u8> = Vec::with_capacity(1000);
    for _ in 0..vec.capacity() {
        vec.push(rand::random());
    }

    c.bench_function("HEX DATA 1000", |b| {
        b.iter(|| get_data_repr(black_box(vec.clone()), black_box(Repr::ASCII)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
