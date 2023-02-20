use cryptopals::sets;

fn main() {
    if let Err(e) = sets::main() {
        eprintln!("Error {e}");
    }
}
