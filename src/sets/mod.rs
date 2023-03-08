pub mod set1;
pub mod set2;
pub mod set3;

pub fn main() -> anyhow::Result<()> {
    set1::main()?;
    set2::main()?;
    set3::main()?;
    Ok(())
}
