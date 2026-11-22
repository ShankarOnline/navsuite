//! Read-only: prints what `disks::list_disks()` finds on this machine.
fn main() {
    match disks::list_disks() {
        Ok(d) => println!("{}", serde_json::to_string_pretty(&d).unwrap()),
        Err(e) => eprintln!("error: {e}"),
    }
}
