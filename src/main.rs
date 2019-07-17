use bist::key;

fn main() {
    let sk = key::read_or_generate_secret_key();
    println!("{:?}", sk);
}
