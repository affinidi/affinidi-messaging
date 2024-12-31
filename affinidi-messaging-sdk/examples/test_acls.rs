use affinidi_messaging_sdk::{
    config::Config,
    errors::ATMError,
    protocols::{
        mediator::global_acls::{GlobalACLMode, GlobalACLSet},
        Protocols,
    },
    ATM,
};

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // Create a new ATM Client
    let atm = ATM::new(Config::builder().build()?).await?;
    let protocols = Protocols::new();

    let test = GlobalACLSet::from_acl_string("deny_all", GlobalACLMode::ExplicitDeny)?;

    println!("{:x}", test.into_bits());

    let test2 = GlobalACLSet::from_bits(test.into_bits());
    println!("{:x}", test2.into_bits());
    Ok(())
}
