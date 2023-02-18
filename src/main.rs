use cryptopals::sets::set1;

fn main() {
    if let Err(e) = set1::main() {
        eprintln!("Error {e}");
    }
}
