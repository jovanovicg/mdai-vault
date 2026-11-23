//! Negativni testovi: oštećeni i podmetnuti ulazi. Pravilo za sve: ⛔ panika,
//! ⛔ oštećen fajl prikazan kao ispravan, greška umjesto sadržaja.

mod common;
use common::*;
use mdai_vault::*;
use std::fs;

fn jedna_biljeska(name: &str) -> (std::path::PathBuf, Vault, LocalState, String) {
    let (dir, c) = new_vault(name);
    let v = c.vault;
    let mut l = LocalState::new();
    let id = v.create_file(&mut l, Kind::Note, "Notes/a.md", b"tajni tekst zeleni-kit-7731").unwrap();
    (dir, v, l, id)
}

/// Fajl odsječen na svakoj od ~60 pozicija (uključujući 0 bajtova): scan javlja problem,
/// read_file vraća grešku, nijedan unos nije prikazan.
#[test]
fn odsjecen_na_svakoj_poziciji() {
    let (dir, v, _l, id) = jedna_biljeska("odsjecen");
    let f = dir.join(format!("{id}.age"));
    let full = fs::read(&f).unwrap();
    let mut cuts: Vec<usize> = (0..full.len()).step_by(full.len() / 50 + 1).collect();
    cuts.extend([1, 20, 100, full.len() - 17, full.len() - 1]);
    for cut in cuts {
        fs::write(&f, &full[..cut]).unwrap();
        let mut fresh = LocalState::new();
        let r = v.scan(&mut fresh).unwrap();
        assert!(r.problem(&format!("{id}.age")).is_some(), "odsječak {cut}: nema problema");
        assert!(r.entries.is_empty(), "odsječak {cut}: prikazan kao ispravan");
        assert!(v.read_file(&id).is_err(), "odsječak {cut}: read_file vratio sadržaj");
    }
    // kontrola: cijeli fajl prolazi
    fs::write(&f, &full).unwrap();
    assert_eq!(v.scan(&mut LocalState::new()).unwrap().entries.len(), 1);
}

/// Jedan izmijenjen bajt na ~80 pozicija kroz cijeli fajl: uvijek problem, nikad sadržaj.
#[test]
fn jedan_bajt_izmijenjen_bilo_gdje() {
    let (dir, v, _l, id) = jedna_biljeska("bajt");
    let f = dir.join(format!("{id}.age"));
    let full = fs::read(&f).unwrap();
    for pos in (0..full.len()).step_by(full.len() / 80 + 1) {
        let mut b = full.clone();
        b[pos] ^= 0x01;
        fs::write(&f, &b).unwrap();
        let r = v.scan(&mut LocalState::new()).unwrap();
        assert!(r.entries.is_empty(), "bajt {pos}: oštećen fajl prikazan kao ispravan");
        assert!(r.problem(&format!("{id}.age")).is_some(), "bajt {pos}: nema problema");
        assert!(v.read_file(&id).is_err(), "bajt {pos}: read_file vratio sadržaj");
    }
}

/// Smeće sa imenom koje liči na fajl trezora: prazan, nasumičan, tekst, age zaglavlje bez tijela.
#[test]
fn smece_sa_imenom_trezora() {
    let (dir, v, mut l, id) = jedna_biljeska("smece");
    let names = [
        ("00000000000000000000000000000001.age", Vec::new()),
        ("00000000000000000000000000000002.age", (0..5000).map(|_| rand::random::<u8>()).collect()),
        ("00000000000000000000000000000003.age", b"# obicna biljeska\n".to_vec()),
        ("00000000000000000000000000000004.age", b"age-encryption.org/v1\n".to_vec()),
        ("ne-hex-ime.age", b"x".to_vec()),
    ];
    for (n, b) in &names {
        fs::write(dir.join(n), b).unwrap();
    }
    let r = v.scan(&mut l).unwrap();
    for (n, _) in &names {
        assert!(r.problem(n).is_some(), "{n}: nema problema");
    }
    // prava bilješka i dalje radi
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].header.id, id);
}

/// Oštećen vault.json: NijeTrezor ili NepoznatFormat, ⛔ panika, ⛔ otključavanje.
#[test]
fn ostecen_vault_json() {
    let (dir, _c) = new_vault("vj");
    let p = dir.join(".mdai-vault/vault.json");
    let orig = fs::read(&p).unwrap();
    for (bad, ocek) in [
        (b"".to_vec(), "nije"),
        (b"{".to_vec(), "nije"),
        (b"{\"format\":1}".to_vec(), "nije"),
        (b"{\"format\":\"1\",\"vault_id\":\"x\"}".to_vec(), "nije"),
        (b"[]".to_vec(), "nije"),
    ] {
        fs::write(&p, &bad).unwrap();
        let e = Vault::unlock(&dir, PW).err().expect("otključan sa oštećenim vault.json");
        assert!(matches!(e, Error::NijeTrezor), "{ocek}: {:?}", String::from_utf8_lossy(&bad));
    }
    let mut v: serde_json::Value = serde_json::from_slice(&orig).unwrap();
    v["format"] = 2.into();
    fs::write(&p, v.to_string()).unwrap();
    assert!(matches!(Vault::unlock(&dir, PW), Err(Error::NepoznatFormat(2))));
    fs::write(&p, &orig).unwrap();
    assert!(Vault::unlock(&dir, PW).is_ok(), "kontrola: original otključava");
}

/// Oštećen paket ključeva (odsječen, bajt izmijenjen, obrisan): greška, ⛔ panika.
#[test]
fn ostecen_paket_kljuceva() {
    let (dir, c) = new_vault("paket");
    // oporavak u praznom trezoru je odbijen (odluka 8), pa trezor dobija bilješku
    c.vault.create_file(&mut LocalState::new(), Kind::Note, "a.md", b"x").unwrap();
    for (fajl, rijeci) in [("key.pass.age", false), ("key.recovery.age", true)] {
        let p = dir.join(".mdai-vault").join(fajl);
        let orig = fs::read(&p).unwrap();
        let mut flip = orig.clone();
        let n = flip.len() / 2;
        flip[n] ^= 0x80;
        for bad in [orig[..orig.len() / 2].to_vec(), flip, Vec::new()] {
            fs::write(&p, &bad).unwrap();
            let r = if rijeci { Vault::unlock_with_recovery(&dir, &c.recovery_words).err() } else { Vault::unlock(&dir, PW).err() };
            assert!(r.is_some(), "{fajl}: otključan oštećenim paketom");
        }
        fs::remove_file(&p).unwrap();
        let r = if rijeci { Vault::unlock_with_recovery(&dir, &c.recovery_words).err() } else { Vault::unlock(&dir, PW).err() };
        assert!(r.is_some(), "{fajl}: otključan bez paketa");
        fs::write(&p, &orig).unwrap();
    }
    assert!(Vault::unlock(&dir, PW).is_ok());
    assert!(Vault::unlock_with_recovery(&dir, &c.recovery_words).is_ok());
}

/// Pogrešne riječi: broj, nepoznata riječ, pogrešan checksum, prazno.
#[test]
fn pogresne_rijeci() {
    let (dir, c) = new_vault("rijeci");
    c.vault.create_file(&mut LocalState::new(), Kind::Note, "a.md", b"x").unwrap();
    let w: Vec<&str> = c.recovery_words.split_whitespace().collect();
    let mut zamijenjena = w.clone();
    zamijenjena[5] = if w[5] == "abandon" { "ability" } else { "abandon" };
    let mut nepoznata = w.clone();
    nepoznata[0] = "mdaiiii";
    for bad in [
        String::new(),
        w[..23].join(" "),
        format!("{} {}", w.join(" "), w[0]),
        zamijenjena.join(" "),
        nepoznata.join(" "),
    ] {
        assert!(matches!(words_to_key_bytes(&bad), Err(Error::PogresneRijeci)), "prihvaćeno: {bad}");
        assert!(Vault::unlock_with_recovery(&dir, &bad).is_err());
    }
    // ispravne riječi drugog trezora: format ispravan, ali ne otvaraju ovaj
    let (_d2, c2) = new_vault("rijeci2");
    assert!(words_to_key_bytes(&c2.recovery_words).is_ok());
    assert!(Vault::unlock_with_recovery(&dir, &c2.recovery_words).is_err());
    // kontrola: tačne riječi otvaraju
    assert!(Vault::unlock_with_recovery(&dir, &c.recovery_words).is_ok());
}

/// Predugačka putanja i nepoznat ID: greška, ⛔ upis na disk.
#[test]
fn neispravni_upisi() {
    let (dir, v, mut l, _id) = jedna_biljeska("upisi");
    let prije = fs::read_dir(&dir).unwrap().count();
    let duga = format!("{}.md", "a".repeat(2000));
    assert!(matches!(v.create_file(&mut l, Kind::Note, &duga, b"x"), Err(Error::PredugackaPutanja)));
    assert!(v.write_file(&mut l, "ffffffffffffffffffffffffffffffff", "x.md", b"x").is_err());
    assert!(v.delete_file(&mut l, "ffffffffffffffffffffffffffffffff").is_err());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), prije, "neuspio upis ostavio fajl");
}

/// Oštećeno lokalno stanje uređaja: greška, ⛔ panika, ⛔ tiho prazno stanje.
#[test]
fn osteceno_lokalno_stanje() {
    let (_dir, v, l, _id) = jedna_biljeska("lokalno");
    let p = tmpdir("lokalno-stanje");
    fs::create_dir_all(&p).unwrap();
    let f = p.join("stanje.age");
    v.save_local_state(&l, &f).unwrap();
    let orig = fs::read(&f).unwrap();
    for bad in [Vec::new(), orig[..orig.len() / 2].to_vec(), b"{}".to_vec()] {
        fs::write(&f, &bad).unwrap();
        assert!(v.load_local_state(&f).is_err(), "oštećeno stanje učitano");
    }
    // stanje drugog trezora se ne smije učitati
    let (_d2, c2) = new_vault("lokalno2");
    fs::write(&f, &orig).unwrap();
    assert!(c2.vault.load_local_state(&f).is_err(), "stanje drugog trezora učitano");
    assert!(v.load_local_state(&f).is_ok());
}
