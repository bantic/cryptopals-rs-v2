pub mod set1;
pub mod set2;

pub fn main() -> anyhow::Result<()> {
    set1::main()?;
    set2::main()?;
    Ok(())
}
