//! Napravi probni trezor u datom folderu i ispiši 24 riječi, AGE-SECRET-KEY i putanju
//! jednog fajla, da se ručno provjeri `age -d -i ključ.txt <fajl>` (spec §3a).
//! `cargo run --example bez_mdai -- /tmp/probni-trezor`
use mdai_vault::*;

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("folder"));
    let c = Vault::create(&dir, "proba", CreateOptions::insecure_fast_for_tests()).unwrap();
    let mut l = LocalState::new();
    let id = c.vault.create_file(&mut l, Kind::Note, "Notes/plan.md", b"# Plan\n").unwrap();
    println!("RIJECI={}", *c.recovery_words);
    println!("KLJUC={}", *words_to_age_secret(&c.recovery_words).unwrap());
    println!("FAJL={}", dir.join(format!("{id}.age")).display());
}
