//! Testovi po tabeli S3 iz `SPEC-FORMAT-TREZORA-V1.md` §6 i tokovima §5.
//! Oblak se simulira direktnim radom nad fajlovima; ponašanje pravih klijenata ⛔ dokazano.

mod common;
use common::*;
use mdai_vault::*;
use std::fs;
use std::str::FromStr;

// ------------------------------------------------------------------ tokovi 1–4

#[test]
fn tok_1_2_kreiranje_otkljucavanje_pogresna_lozinka() {
    let (dir, c) = new_vault("tok12");
    assert_eq!(c.recovery_words.split_whitespace().count(), 24);
    assert!(dir.join(".mdai-vault/vault.json").exists());
    assert!(dir.join(".mdai-vault/key.pass.age").exists());
    assert!(dir.join(".mdai-vault/key.recovery.age").exists());
    let v = Vault::unlock(&dir, PW).unwrap();
    assert_eq!(v.vault_id(), c.vault.vault_id());
    assert!(matches!(Vault::unlock(&dir, "pogresna"), Err(Error::PogresnaLozinka)));
    // vault.json nosi samo format i vault_id
    let vj: serde_json::Value = serde_json::from_slice(&fs::read(dir.join(".mdai-vault/vault.json")).unwrap()).unwrap();
    assert_eq!(vj.as_object().unwrap().len(), 2);
}

#[test]
fn tok_1_kreiranje_odbija_neprazan_folder() {
    let dir = tmpdir("neprazan");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("x.md"), "x").unwrap();
    assert!(matches!(Vault::create(&dir, PW, opts()), Err(Error::VecPostoji)));
}

#[test]
fn tok_3_4_zapis_citanje_ravan_raspored() {
    let (dir, c) = new_vault("tok34");
    let v = c.vault;
    let mut l = LocalState::new();
    let id = v.create_file(&mut l, Kind::Note, "Notes/2026/sastanak.md", b"# Sastanak\ntekst").unwrap();
    let (h, b) = v.read_file(&id).unwrap();
    assert_eq!(h.path, "Notes/2026/sastanak.md");
    assert_eq!(h.rev, 1);
    assert_eq!(&b[..], b"# Sastanak\ntekst");
    // ravan raspored: nijedan podfolder osim .mdai-vault (R14)
    let dirs: Vec<_> = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.path().is_dir()).map(|e| e.file_name()).collect();
    assert_eq!(dirs, vec![std::ffi::OsString::from(".mdai-vault")]);
    assert!(dir.join(format!("{id}.age")).exists());
    v.write_file(&mut l, &id, "Notes/2026/sastanak.md", b"druga").unwrap();
    assert_eq!(v.read_file(&id).unwrap().0.rev, 2);
    let r = v.scan(&mut l).unwrap();
    assert_eq!(r.entry(&id).unwrap().status, Status::Isto);
    assert!(l.own.is_empty(), "potvrđen upis se briše iz `own`");
}

// ------------------------------------------------------------------ tabela S3

#[test]
fn s3_1_kopija_provajdera() {
    let (dir, c) = new_vault("s31");
    let v = c.vault;
    let (mut a, mut b) = (LocalState::new(), LocalState::new());
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    v.scan(&mut a).unwrap();
    v.scan(&mut b).unwrap();
    let a2 = offline_write(&v, &mut a, &dir, &id, "n.md", b"A");
    let b2 = offline_write(&v, &mut b, &dir, &id, "n.md", b"B");
    fs::write(dir.join(format!("{id}.age")), &b2).unwrap();
    fs::write(dir.join(format!("{id} (conflicted copy 2026-11-18).age")), &a2).unwrap();
    for l in [&mut a, &mut b] {
        let r = v.scan(l).unwrap();
        let k = r.conflicts.get(&id).expect("sukob prepoznat po ID-u (R2)");
        let bodies: Vec<_> = k.iter().map(|e| e.body.to_vec()).collect();
        assert!(bodies.contains(&b"A".to_vec()) && bodies.contains(&b"B".to_vec()));
        assert!(k.iter().all(|e| !e.ime_ne_odgovara));
    }
    // rješavanje: korisnik spoji, pa tek onda kopija smije da se ukloni
    let r = v.scan(&mut a).unwrap();
    let copy = format!("{id} (conflicted copy 2026-11-18).age");
    assert!(v.remove_copy(&copy).is_err(), "kopija se ne briše prije rješenja");
    v.resolve_conflict(&mut a, &r, &id, "n.md", b"A+B").unwrap();
    v.remove_copy(&copy).unwrap();
    let r = v.scan(&mut b).unwrap();
    assert!(r.conflicts.is_empty());
    assert_eq!(&r.entry(&id).unwrap().body[..], b"A+B");
    assert_eq!(r.entry(&id).unwrap().status, Status::Napred);
}

#[test]
fn s3_2_tihi_gubitak_racva() {
    let (dir, c) = new_vault("s32");
    let v = c.vault;
    let (mut a, mut b) = (LocalState::new(), LocalState::new());
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    v.scan(&mut a).unwrap();
    v.scan(&mut b).unwrap();
    let _a2 = offline_write(&v, &mut a, &dir, &id, "n.md", b"tekst sa A");
    let b2 = offline_write(&v, &mut b, &dir, &id, "n.md", b"tekst sa B");
    fs::write(dir.join(format!("{id}.age")), &b2).unwrap(); // oblak tiho zadrži B
    let r = v.scan(&mut b).unwrap();
    assert_eq!(r.entry(&id).unwrap().status, Status::Isto);
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.entry(&id).unwrap().status, Status::Racva { moja_dostupna: true });
    let new_id = v.resolve_fork(&mut a, &r, &id).unwrap().expect("A tekst vraćen");
    let r = v.scan(&mut a).unwrap();
    assert_eq!(&r.entry(&new_id).unwrap().body[..], b"tekst sa A");
    assert!(r.entry(&new_id).unwrap().header.path.starts_with("n (sukob "));
    assert_eq!(&r.entry(&id).unwrap().body[..], b"tekst sa B");
    assert_eq!(r.entry(&id).unwrap().status, Status::Isto);
}

#[test]
fn s3_3_vise_verzija_napred() {
    let (_dir, c) = new_vault("s33");
    let v = c.vault;
    let (mut a, mut b) = (LocalState::new(), LocalState::new());
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    v.scan(&mut b).unwrap();
    v.write_file(&mut b, &id, "n.md", b"v2").unwrap();
    v.write_file(&mut b, &id, "n.md", b"v3").unwrap();
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.entry(&id).unwrap().status, Status::Napred);
    assert!(a.own.is_empty());
}

#[test]
fn s3_4_brisanje_naspram_izmjene() {
    // (a) oblak zadrži izmjenu: A (brisao) prihvata izmjenu, ništa se ne vraća
    let (dir, c) = new_vault("s34a");
    let v = c.vault;
    let (mut a, mut b) = (LocalState::new(), LocalState::new());
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    v.scan(&mut a).unwrap();
    v.scan(&mut b).unwrap();
    let _tomb = offline_delete(&v, &mut a, &dir, &id);
    let b2 = offline_write(&v, &mut b, &dir, &id, "n.md", b"izmjena B");
    fs::write(dir.join(format!("{id}.age")), &b2).unwrap();
    let r = v.scan(&mut a).unwrap();
    assert!(matches!(r.entry(&id).unwrap().status, Status::Racva { .. }));
    assert_eq!(v.resolve_fork(&mut a, &r, &id).unwrap(), None);
    assert_eq!(&v.scan(&mut a).unwrap().entry(&id).unwrap().body[..], b"izmjena B");

    // (b) oblak zadrži kamen: B (mijenjao) vraća svoju izmjenu kao novu bilješku
    let (dir, c) = new_vault("s34b");
    let v = c.vault;
    let (mut a, mut b) = (LocalState::new(), LocalState::new());
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    v.scan(&mut a).unwrap();
    v.scan(&mut b).unwrap();
    let tomb = offline_delete(&v, &mut a, &dir, &id);
    let _b2 = offline_write(&v, &mut b, &dir, &id, "n.md", b"izmjena B");
    fs::write(dir.join(format!("{id}.age")), &tomb).unwrap();
    let r = v.scan(&mut b).unwrap();
    assert!(r.entry(&id).unwrap().header.deleted);
    let new_id = v.resolve_fork(&mut b, &r, &id).unwrap().unwrap();
    assert_eq!(&v.read_file(&new_id).unwrap().1[..], b"izmjena B");
}

#[test]
fn s3_5_nestao_bez_kamena() {
    let (dir, c) = new_vault("s35");
    let v = c.vault;
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    let id2 = v.create_file(&mut a, Kind::Note, "obrisana.md", b"x").unwrap();
    v.delete_file(&mut a, &id2).unwrap();
    v.scan(&mut a).unwrap();
    fs::remove_file(dir.join(format!("{id}.age"))).unwrap();
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.missing, vec![id]);
    assert!(r.entry(&id2).unwrap().header.deleted, "kamen ostaje, nije `nestao`");
}

#[test]
fn s3_6_prekinut_prenos() {
    let (dir, c) = new_vault("s36");
    let v = c.vault;
    let mut a = LocalState::new();
    let big = vec![b'x'; 200_000]; // više age STREAM komada
    let id = v.create_file(&mut a, Kind::Asset, "slika.png", &big).unwrap();
    let id_small = v.create_file(&mut a, Kind::Note, "n.md", b"kratko").unwrap();
    for (i, cut) in [(id.clone(), 70_000usize), (id_small.clone(), 300)] {
        let f = dir.join(format!("{i}.age"));
        let bytes = fs::read(&f).unwrap();
        fs::write(&f, &bytes[..cut.min(bytes.len() - 1)]).unwrap();
    }
    // i fajl odsječen tačno na granici age STREAM komada (fali zadnji komad)
    let id_edge = v.create_file(&mut a, Kind::Asset, "b.png", &big).unwrap();
    let f = dir.join(format!("{id_edge}.age"));
    let bytes = fs::read(&f).unwrap();
    let pt_len = 200_000 + HEADER_LEN + 64; // tijelo + zaglavlje + dva taga
    let pt_total = pt_len.div_ceil(BUCKET) * BUCKET;
    let last_chunk_ct = pt_total % 65_536 + 16;
    fs::write(&f, &bytes[..bytes.len() - last_chunk_ct]).unwrap();
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.problem(&format!("{id_edge}.age")), Some(&Problem::Nepotpun));
    assert_eq!(r.problem(&format!("{id}.age")), Some(&Problem::Nepotpun));
    assert_eq!(r.problem(&format!("{id_small}.age")), Some(&Problem::Nepotpun));
    assert!(r.entries.is_empty(), "nijedan odsječen fajl nije prikazan kao ispravan");
}

#[test]
fn s3_7_rollback() {
    let (dir, c) = new_vault("s37");
    let v = c.vault;
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    let f = dir.join(format!("{id}.age"));
    let old = fs::read(&f).unwrap();
    v.write_file(&mut a, &id, "n.md", b"v2").unwrap();
    v.scan(&mut a).unwrap();
    fs::write(&f, old).unwrap();
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.entry(&id).unwrap().status, Status::Vraceno { disk_rev: 1, known_rev: 2 });
    assert_eq!(a.known[&id].rev, 2, "lokalno stanje ne ide unazad samo");
}

fn forged_header(v: &Vault, id: &str) -> Header {
    Header {
        v: 1, vault: v.vault_id().into(), gen: v.generation(), id: id.into(), kind: Kind::Note,
        path: "podmetnuto.md".into(), rev: 99, anc: vec![], dev: "napadac".into(), deleted: false, len: 4,
    }
}

#[test]
fn s3_8_podmetnut_bez_maca() {
    let (dir, c) = new_vault("s38");
    let v = c.vault;
    let mut a = LocalState::new();
    v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    // napadač zna javni ključ trezora (pretpostavka: procurio), ali ne i mac_key
    let pubkey = age::x25519::Recipient::from_str(&v.vault_recipient()).unwrap();
    let id = "00112233445566778899aabbccddeeff";
    let pt = build_plaintext(&forged_header(&v, id), b"laz!", &[7u8; 32]).unwrap();
    fs::write(dir.join(format!("{id}.age")), age_encrypt_to(&[&pubkey], &pt)).unwrap();
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.problem(&format!("{id}.age")), Some(&Problem::Neautentican));
    assert!(r.entry(id).is_none());
    // kontrola: sa pravim mac_key bi prošao (dakle test mjeri baš MAC)
    let pt = build_plaintext(&forged_header(&v, id), b"laz!", &v.mac_key_for_tests()).unwrap();
    fs::write(dir.join(format!("{id}.age")), age_encrypt_to(&[&pubkey], &pt)).unwrap();
    assert!(v.scan(&mut a).unwrap().entry(id).is_some());
}

#[test]
fn s3_9_podmetnut_tudj() {
    let (dir, c) = new_vault("s39");
    let v = c.vault;
    let mut a = LocalState::new();
    let other = age::x25519::Identity::generate();
    fs::write(dir.join("ffffffffffffffffffffffffffffffff.age"), age_encrypt_to(&[&other.to_public()], b"x")).unwrap();
    let r = v.scan(&mut a).unwrap();
    assert_eq!(r.problem("ffffffffffffffffffffffffffffffff.age"), Some(&Problem::Tudj));
    // fajl iz DRUGOG mdai trezora istog korisnika je takođe tuđ
    let (_d2, c2) = new_vault("s39b");
    let mut l2 = LocalState::new();
    let id2 = c2.vault.create_file(&mut l2, Kind::Note, "x.md", b"x").unwrap();
    fs::copy(_d2.join(format!("{id2}.age")), dir.join(format!("{id2}.age"))).unwrap();
    assert_eq!(v.scan(&mut a).unwrap().problem(&format!("{id2}.age")), Some(&Problem::Tudj));
}

#[test]
fn s3_10_zamjena_imena() {
    let (dir, c) = new_vault("s310");
    let v = c.vault;
    let mut a = LocalState::new();
    let x = v.create_file(&mut a, Kind::Note, "x.md", b"X").unwrap();
    let y = v.create_file(&mut a, Kind::Note, "y.md", b"Y").unwrap();
    v.scan(&mut a).unwrap();
    let (fx, fy, t) = (dir.join(format!("{x}.age")), dir.join(format!("{y}.age")), dir.join("t"));
    fs::rename(&fx, &t).unwrap();
    fs::rename(&fy, &fx).unwrap();
    fs::rename(&t, &fy).unwrap();
    let r = v.scan(&mut a).unwrap();
    let ex = r.entry(&x).unwrap();
    assert!(ex.ime_ne_odgovara);
    assert_eq!(&ex.body[..], b"X", "sadržaj ostaje vezan za svoj ID");
    assert_eq!(ex.header.path, "x.md");
}

#[test]
fn s3_11_vault_json_primaoci_novi_model_zeleno() {
    let (dir, c) = new_vault("s311");
    let attacker = age::x25519::Identity::generate();
    let p = dir.join(".mdai-vault/vault.json");
    let mut vj: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    vj["recipients"] = serde_json::json!([attacker.to_public().to_string()]);
    vj["kdf"] = serde_json::json!("none");
    fs::write(&p, vj.to_string()).unwrap();
    drop(c);
    let v = Vault::unlock(&dir, PW).unwrap();
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "tajna.md", b"tajna").unwrap();
    let ct = fs::read(dir.join(format!("{id}.age"))).unwrap();
    assert!(age_decrypt_with(&attacker, &ct).is_none(), "napadač ne čita nov fajl");
}

#[test]
fn stari_model_r7_crveno() {
    let dir = tmpdir("stari-r7");
    let _vault_key = stari::create(&dir);
    let attacker = age::x25519::Identity::generate();
    let p = dir.join(".mdai-vault/vault.json");
    let mut vj: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    vj["recipients"].as_array_mut().unwrap().push(serde_json::json!(attacker.to_public().to_string()));
    fs::write(&p, vj.to_string()).unwrap();
    stari::write(&dir, "tajna.md", b"tajna");
    let ct = fs::read(dir.join("tajna.md.age")).unwrap();
    assert!(age_decrypt_with(&attacker, &ct).is_some(), "CRVENO: stari model daje tekst napadaču (R7)");
}

#[test]
fn s3_12_veci_format() {
    let (dir, c) = new_vault("s312");
    drop(c);
    let p = dir.join(".mdai-vault/vault.json");
    let mut vj: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    vj["format"] = serde_json::json!(2);
    fs::write(&p, vj.to_string()).unwrap();
    assert!(matches!(Vault::unlock(&dir, PW), Err(Error::NepoznatFormat(2))));
}

#[test]
fn s3_13_podmetnut_recovery() {
    let (dir, c) = new_vault("s313");
    let v = c.vault;
    let words = c.recovery_words.clone();
    let mut a = LocalState::new();
    v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    // napadač zna javni ključ za oporavak (pretpostavka: procurio) i podmeće svoj paket
    let rec = age::x25519::Recipient::from_str(&v.recovery_recipient()).unwrap();
    let evil = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let bundle = serde_json::json!({
        "format": 1, "vault_id": v.vault_id(), "gen": 0,
        "identity": evil.to_string().expose_secret(),
        "mac_key": "11".repeat(32),
        "recovery_recipient": v.recovery_recipient(), "previous": []
    });
    fs::write(dir.join(".mdai-vault/key.recovery.age"), age_encrypt_to(&[&rec], bundle.to_string().as_bytes())).unwrap();
    assert!(matches!(Vault::unlock_with_recovery(&dir, &words), Err(Error::OporavakNeprovjeren)));
}

#[test]
fn s3_14_nista_otvoreno_novi_model_zeleno() {
    let (dir, c) = new_vault("s314");
    let v = c.vault;
    let mut a = LocalState::new();
    v.create_file(&mut a, Kind::Note, "Klijenti/Petrovic ugovor.md", b"Rok isporuke je petak u podne").unwrap();
    v.create_file(&mut a, Kind::Dir, "Klijenti/Arhiva", b"").unwrap();
    v.scan(&mut a).unwrap();
    let state = tmpdir("s314-state").join("stanje.age");
    v.save_local_state(&a, &state).unwrap();
    let needles = ["Petrovic", "ugovor", "Klijenti", "Arhiva", "Rok isporuke", PW];
    assert_eq!(nista_otvoreno(&dir, &needles), Ok(()));
    assert_eq!(nista_otvoreno(state.parent().unwrap(), &needles), Ok(()), "lokalno stanje šifrovano (R11)");
    assert!(v.save_local_state(&a, &dir.join("stanje.age")).is_err(), "stanje ne smije u trezor");
    let back = v.load_local_state(&state).unwrap();
    assert_eq!(back.known, a.known);
}

#[test]
fn stari_model_imena_crveno() {
    let dir = tmpdir("stari-imena");
    stari::create(&dir);
    stari::write(&dir, "Klijenti/Petrovic ugovor.md", b"Rok isporuke je petak u podne");
    assert!(nista_otvoreno(&dir, &["Petrovic", "Klijenti"]).is_err(), "CRVENO: stari model otkriva imena");
}

#[test]
fn s3_15_dopuna() {
    let (dir, c) = new_vault("s315");
    let v = &c.vault;
    let mut a = LocalState::new();
    let long = format!("{}.md", "dugo-ime-".repeat(60));
    let ids = [
        v.create_file(&mut a, Kind::Note, "a.md", b"x").unwrap(),
        v.create_file(&mut a, Kind::Note, &long, b"x").unwrap(),
        v.create_file(&mut a, Kind::Note, "b.md", &vec![b'y'; 2900]).unwrap(),
    ];
    // `age` dodaje nasumičnu „grease“ stavku u zaglavlje, pa se šifrat razlikuje za
    // nekoliko desetina bajtova nezavisno od sadržaja; dopuna se zato mjeri na plaintextu.
    let key = age::x25519::Identity::from_str(&words_to_age_secret(&c.recovery_words).unwrap()).unwrap();
    let pt_sizes: Vec<usize> = ids.iter()
        .map(|i| age_decrypt_with(&key, &fs::read(dir.join(format!("{i}.age"))).unwrap()).unwrap().len())
        .collect();
    assert_eq!(pt_sizes, vec![BUCKET; 3]);
    let sizes: Vec<u64> = ids.iter().map(|i| fs::metadata(dir.join(format!("{i}.age"))).unwrap().len()).collect();
    let (min, max) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
    assert!(max - min < 512, "šifrat se razlikuje samo za grease: {sizes:?}");
    assert!(matches!(v.create_file(&mut a, Kind::Note, &"x".repeat(1100), b""), Err(Error::PredugackaPutanja)));
}

// ------------------------------------------------------------------ tokovi 7–10, R19

#[test]
fn tok_7_promjena_lozinke() {
    let (dir, c) = new_vault("tok7");
    let v = c.vault;
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    let before_file = fs::read(dir.join(format!("{id}.age"))).unwrap();
    let before_rec = fs::read(dir.join(".mdai-vault/key.recovery.age")).unwrap();
    let old_pass = fs::read(dir.join(".mdai-vault/key.pass.age")).unwrap();
    v.change_password("nova lozinka 2026", opts()).unwrap();
    assert!(matches!(Vault::unlock(&dir, PW), Err(Error::PogresnaLozinka)));
    assert!(Vault::unlock(&dir, "nova lozinka 2026").is_ok());
    assert_eq!(fs::read(dir.join(format!("{id}.age"))).unwrap(), before_file, "fajlovi netaknuti");
    assert_eq!(fs::read(dir.join(".mdai-vault/key.recovery.age")).unwrap(), before_rec);
    // ⚠️ granica (spec §5.7): stara kopija key.pass.age iz istorije oblaka i dalje radi sa starom lozinkom
    fs::write(dir.join(".mdai-vault/key.pass.age"), old_pass).unwrap();
    assert!(Vault::unlock(&dir, PW).is_ok());
}

#[test]
fn tok_8_gubitak_lozinke() {
    let (dir, c) = new_vault("tok8");
    let words = c.recovery_words.clone();
    let mut a = LocalState::new();
    let id = c.vault.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    drop(c);
    let v = Vault::unlock_with_recovery(&dir, &words).unwrap();
    v.change_password("nova", opts()).unwrap();
    let v = Vault::unlock(&dir, "nova").unwrap();
    assert_eq!(&v.read_file(&id).unwrap().1[..], b"v1");
    assert!(matches!(Vault::unlock_with_recovery(&dir, "abandon ".repeat(23).trim()), Err(Error::PogresneRijeci)));
}

#[test]
fn tok_8_prazan_trezor_oporavak_odbijen() {
    let (dir, c) = new_vault("tok8p");
    let words = c.recovery_words.clone();
    assert!(matches!(Vault::unlock_with_recovery(&dir, &words), Err(Error::OporavakNeprovjeren)));
}

#[test]
fn tok_9_gubitak_rijeci() {
    let (dir, c) = new_vault("tok9");
    let old_words = c.recovery_words.clone();
    let mut v = c.vault;
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    let new_words = v.new_recovery(PW, opts()).unwrap();
    assert_ne!(*old_words, *new_words);
    let id2 = v.create_file(&mut a, Kind::Note, "m.md", b"posle").unwrap();
    assert!(Vault::unlock_with_recovery(&dir, &new_words).is_ok());
    assert!(Vault::unlock_with_recovery(&dir, &old_words).is_err());
    let old_id = age::x25519::Identity::from_str(&words_to_age_secret(&old_words).unwrap()).unwrap();
    // ⚠️ granica (spec Q9): stare riječi i dalje čitaju STARI fajl, ali ne i novi
    assert!(age_decrypt_with(&old_id, &fs::read(dir.join(format!("{id}.age"))).unwrap()).is_some());
    assert!(age_decrypt_with(&old_id, &fs::read(dir.join(format!("{id2}.age"))).unwrap()).is_none());
}

#[test]
fn tok_10_novi_kljuc_trezora() {
    let (dir, c) = new_vault("tok10");
    let old_words = c.recovery_words.clone();
    let mut v = c.vault;
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"v1").unwrap();
    let old_vault_secret = {
        // stari ključ trezora, kao da je procurio
        let st = tmpdir("tok10-st").join("s.age");
        v.save_local_state(&a, &st).unwrap();
        st
    };
    let _ = old_vault_secret;
    let new_words = v.rotate(&mut a, "nova", opts()).unwrap();
    assert_eq!(v.generation(), 1);
    let ct = fs::read(dir.join(format!("{id}.age"))).unwrap();
    let old_id = age::x25519::Identity::from_str(&words_to_age_secret(&old_words).unwrap()).unwrap();
    assert!(age_decrypt_with(&old_id, &ct).is_none(), "stare riječi ne čitaju prepisan fajl");
    assert!(matches!(Vault::unlock(&dir, PW), Err(Error::PogresnaLozinka)));
    let v2 = Vault::unlock_with_recovery(&dir, &new_words).unwrap();
    assert_eq!(&v2.read_file(&id).unwrap().1[..], b"v1");
    assert_eq!(v2.read_file(&id).unwrap().0.gen, 1);
    let r = v2.scan(&mut a).unwrap();
    assert_eq!(r.entry(&id).unwrap().status, Status::Isto);
}

#[test]
fn r19_rijeci_su_kodiranje_ne_derivacija() {
    let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
    let w = key_bytes_to_words(&bytes);
    assert_eq!(w.split_whitespace().count(), 24);
    assert_eq!(*words_to_key_bytes(&w).unwrap(), bytes);
    // test-vektor: 32 nule ⇒ standardni BIP-39 vektor (entropija 00…00)
    let zero = key_bytes_to_words(&[0u8; 32]);
    assert_eq!(&*zero, &format!("{}art", "abandon ".repeat(23)));
    // pogrešan kontrolni zbir
    assert!(words_to_key_bytes(&"abandon ".repeat(24)).is_err());
    // riječi ⇒ AGE-SECRET-KEY ⇒ isti broj kao age-keygen format
    let s = words_to_age_secret(&w).unwrap();
    assert!(s.starts_with("AGE-SECRET-KEY-1"));
    assert!(age::x25519::Identity::from_str(&s).is_ok());
}

#[test]
fn bez_mdai_ja_rijeci_otvaraju_fajl_obicnim_age() {
    let (dir, c) = new_vault("bezmdai");
    let mut a = LocalState::new();
    let id = c.vault.create_file(&mut a, Kind::Note, "Notes/plan.md", b"# Plan").unwrap();
    let key = age::x25519::Identity::from_str(&words_to_age_secret(&c.recovery_words).unwrap()).unwrap();
    let pt = age_decrypt_with(&key, &fs::read(dir.join(format!("{id}.age"))).unwrap()).unwrap();
    let end = pt[..HEADER_LEN].iter().position(|&b| b == 0).unwrap();
    let h: serde_json::Value = serde_json::from_slice(&pt[..end]).unwrap();
    assert_eq!(h["path"], "Notes/plan.md");
    let len = h["len"].as_u64().unwrap() as usize;
    assert_eq!(&pt[HEADER_LEN + 32..HEADER_LEN + 32 + len], b"# Plan");
}

// ------------------------------------------------------------------ kompatibilnost formata

/// Trezor u `tests/fixtures/trezor-age-0.11.5/` napisan je crate-om nad `age 0.11.5`
/// (commit 4ba9c4d, prije prelaska na 0.12.1; lozinka `proba`, riječi u `.rijeci`).
/// Test dokazuje da ga crate nad 0.12.1 otvara lozinkom i riječima i da ga ovjerava.
#[test]
fn format_isti_poslije_age_0_12_1() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trezor-age-0.11.5");
    let dir = tmpdir("fixture0115");
    fs::create_dir_all(dir.join(".mdai-vault")).unwrap();
    for e in fs::read_dir(&src).unwrap().chain(fs::read_dir(src.join(".mdai-vault")).unwrap()) {
        let p = e.unwrap().path();
        if p.is_file() {
            let rel = p.strip_prefix(&src).unwrap();
            fs::copy(&p, dir.join(rel)).unwrap();
        }
    }
    let v = Vault::unlock(&dir, "proba").unwrap();
    let mut l = LocalState::new();
    let r = v.scan(&mut l).unwrap();
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.entries.len(), 1);
    let e = &r.entries[0];
    assert_eq!(e.header.path, "Notes/plan.md");
    assert_eq!(&e.body[..], b"# Plan\n");
    assert_eq!(e.status, Status::Novo);
    let words = fs::read_to_string(src.parent().unwrap().join("trezor-age-0.11.5.rijeci")).unwrap();
    assert!(Vault::unlock_with_recovery(&dir, words.trim()).is_ok());
    // i obrnuto u istom fajlu: upis 0.12.1 se čita dalje
    v.write_file(&mut l, &e.header.id, "Notes/plan.md", b"# Plan v2\n").unwrap();
    assert_eq!(&v.read_file(&e.header.id).unwrap().1[..], b"# Plan v2\n");
}

// ------------------------------------------------------------------ SEG 13 (1.3.9): paket u sefu uređaja

#[test]
fn seg13_paket_otvara_trezor_i_zastari_poslije_rotacije() {
    let (dir, c) = new_vault("seg13");
    assert_eq!(Vault::peek_vault_id(&dir).unwrap(), c.vault.vault_id());
    let mut v = c.vault;
    // prazan trezor: paket otvara (nema fajla koji bi ga ovjerio ni osporio)
    let paket = v.key_bundle();
    assert!(Vault::unlock_with_bundle(&dir, &paket).is_ok());
    let mut a = LocalState::new();
    let id = v.create_file(&mut a, Kind::Note, "n.md", b"tajna").unwrap();
    let paket = v.key_bundle();
    let v2 = Vault::unlock_with_bundle(&dir, &paket).unwrap();
    assert_eq!(&v2.read_file(&id).unwrap().1[..], b"tajna");
    // smeće i paket drugog trezora ⇒ odbijeno
    assert!(matches!(Vault::unlock_with_bundle(&dir, b"{}"), Err(Error::KljucZastario)));
    let (_d2, c2) = new_vault("seg13-drugi");
    assert!(matches!(Vault::unlock_with_bundle(&dir, &c2.vault.key_bundle()), Err(Error::DrugiTrezor)));
    // rotacija na „drugom uređaju“ ⇒ stari paket iz sefa ⛔ otvara
    v.rotate(&mut a, PW, opts()).unwrap();
    assert!(matches!(Vault::unlock_with_bundle(&dir, &paket), Err(Error::KljucZastario)));
    assert!(Vault::unlock_with_bundle(&dir, &v.key_bundle()).is_ok());
}
