use bist::key;

fn main() {
    let (_sk, pk) = key::read_or_generate_keys();
    let addr = key::address(&pk);
    println!("{}", addr);
}
