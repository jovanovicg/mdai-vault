//! Pomoćno za testove: privremeni folderi, „offline“ upis, i STARI model (spec 28.10.)
//! da bi isti test bio crven nad starim, a zelen nad novim.
#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use mdai_vault::*;

pub const PW: &str = "konj baterija spajalica 42";

pub fn tmpdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("mdai-vault-test-{name}-{:016x}", rand::random::<u64>()));
    let _ = fs::remove_dir_all(&p);
    p
}

pub fn opts() -> CreateOptions {
    CreateOptions::insecure_fast_for_tests()
}

pub fn new_vault(name: &str) -> (PathBuf, Created) {
    let dir = tmpdir(name);
    let c = Vault::create(&dir, PW, opts()).expect("create");
    (dir, c)
}

/// Upis koji se desio na uređaju bez mreže: vrati bajtove te verzije i ostavi disk
/// kakav je bio prije (simulacija da oblak još nije vidio izmjenu).
pub fn offline_write(v: &Vault, local: &mut LocalState, dir: &Path, id: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let f = dir.join(format!("{id}.age"));
    let before = fs::read(&f).unwrap();
    v.write_file(local, id, path, body).unwrap();
    let after = fs::read(&f).unwrap();
    fs::write(&f, before).unwrap();
    after
}

pub fn offline_delete(v: &Vault, local: &mut LocalState, dir: &Path, id: &str) -> Vec<u8> {
    let f = dir.join(format!("{id}.age"));
    let before = fs::read(&f).unwrap();
    v.delete_file(local, id).unwrap();
    let after = fs::read(&f).unwrap();
    fs::write(&f, before).unwrap();
    after
}

/// Svi bajtovi svih fajlova u folderu (rekurzivno), za traženje otvorenog teksta.
pub fn all_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    fn walk(d: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in fs::read_dir(d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            out.push((p.to_string_lossy().into_owned(), vec![]));
            if p.is_dir() {
                walk(&p, out);
            } else {
                let n = out.len() - 1;
                out[n].1 = fs::read(&p).unwrap();
            }
        }
    }
    walk(dir, &mut out);
    out
}

/// Provjera „ništa otvoreno“: nijedan traženi niz ni u imenu ni u sadržaju. Err = nađeno.
pub fn nista_otvoreno(dir: &Path, needles: &[&str]) -> std::result::Result<(), String> {
    for (name, bytes) in all_bytes(dir) {
        for n in needles {
            if name.contains(n) {
                return Err(format!("ime: {name} sadrži {n}"));
            }
            if bytes.windows(n.len()).any(|w| w == n.as_bytes()) {
                return Err(format!("sadržaj: {name} sadrži {n}"));
            }
        }
    }
    Ok(())
}

pub fn age_decrypt_with(identity: &age::x25519::Identity, bytes: &[u8]) -> Option<Vec<u8>> {
    let d = age::Decryptor::new_buffered(bytes).ok()?;
    let mut r = d.decrypt(std::iter::once(identity as &dyn age::Identity)).ok()?;
    let mut out = vec![];
    r.read_to_end(&mut out).ok()?;
    Some(out)
}

pub fn age_encrypt_to(recipients: &[&dyn age::Recipient], pt: &[u8]) -> Vec<u8> {
    let enc = age::Encryptor::with_recipients(recipients.iter().copied()).unwrap();
    let mut out = vec![];
    let mut w = enc.wrap_output(&mut out).unwrap();
    w.write_all(pt).unwrap();
    w.finish().unwrap();
    out
}

// ------------------------------------------------------------------ STARI MODEL (28.10.)
// `docs/VAULT-ENKRIPCIJA-SPEC.md` §3 na main: `nota.md.age` (vidljivo ime), primaoci iz
// `vault.json` u oblaku. Namjerno minimalno: samo ono što testovi upoređuju.

pub mod stari {
    use super::*;

    pub fn create(dir: &Path) -> age::x25519::Identity {
        fs::create_dir_all(dir.join(".mdai-vault")).unwrap();
        let id = age::x25519::Identity::generate();
        let vj = serde_json::json!({"format":1,"cipher":"age-v1","recipients":[id.to_public().to_string()],"kdf":"age-scrypt"});
        fs::write(dir.join(".mdai-vault/vault.json"), vj.to_string()).unwrap();
        id
    }

    /// Upis po starom spec-u: primaoci se čitaju iz `vault.json` (R7).
    pub fn write(dir: &Path, path: &str, body: &[u8]) {
        let vj: serde_json::Value = serde_json::from_slice(&fs::read(dir.join(".mdai-vault/vault.json")).unwrap()).unwrap();
        let recips: Vec<age::x25519::Recipient> = vj["recipients"].as_array().unwrap().iter()
            .map(|r| age::x25519::Recipient::from_str(r.as_str().unwrap()).unwrap()).collect();
        let refs: Vec<&dyn age::Recipient> = recips.iter().map(|r| r as &dyn age::Recipient).collect();
        let ct = age_encrypt_to(&refs, body);
        let p = dir.join(format!("{path}.age"));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, ct).unwrap();
    }
}
