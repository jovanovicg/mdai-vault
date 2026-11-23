//! Referentna implementacija formata trezora v1 (vidi `SPEC-FORMAT-TREZORA-V1.md`).
//!
//! Samo jezgro formata: nema UI-ja, Tauri-ja, mreže ni telemetrije. Kriptografija je
//! isključivo `age` (X25519 + scrypt) i HMAC-SHA256 za autentičnost (spec §3 R8).
//! Ništa se ne izvodi iz lozinke ni iz riječi osim onoga što `age` sam radi (scrypt).
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::iter;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------- konstante formata

/// Verzija formata. Veća vrijednost u `vault.json` ili paketu ⇒ odbij.
pub const FORMAT: u32 = 1;
/// Fiksna veličina zaglavlja u plaintextu (spec §2, R13).
pub const HEADER_LEN: usize = 1024;
/// Dužina HMAC-SHA256 taga.
pub const TAG_LEN: usize = 32;
/// Plaintext se zaokružuje na umnožak ovoga (spec §2, R13).
pub const BUCKET: usize = 4096;
/// Najviše predaka u `anc` (spec §2, R3).
pub const MAX_ANC: usize = 16;
/// Najmanji scrypt `log_n` za prave trezore (spec Q2).
pub const MIN_LOG_N: u8 = 18;

const DIR: &str = ".mdai-vault";
const VAULT_JSON: &str = "vault.json";
const KEY_PASS: &str = "key.pass.age";
const KEY_RECOVERY: &str = "key.recovery.age";
const TMP: &str = "tmp";
const LABEL_HEADER: &[u8] = b"mdai-vault/v1/header";
const LABEL_FILE: &[u8] = b"mdai-vault/v1/file";
const AGE_SECRET_HRP: &str = "age-secret-key-";

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------- greške

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Folder već sadrži trezor ili nije prazan.
    VecPostoji,
    /// Nema `.mdai-vault/vault.json`.
    NijeTrezor,
    /// Pogrešna lozinka (ili podmetnut `key.pass.age`).
    PogresnaLozinka,
    /// Pogrešne riječi za oporavak.
    PogresneRijeci,
    /// `vault.json` ili paket kažu format koji ova verzija ne zna (spec Q8).
    NepoznatFormat(u64),
    /// `vault_id` u `vault.json` i u paketu se razlikuju.
    DrugiTrezor,
    /// Paket iz `key.recovery.age` ne ovjerava nijedan postojeći fajl (spec §5.8).
    OporavakNeprovjeren,
    /// Zaglavlje prelazi 1024 bajta (predugačka putanja).
    PredugackaPutanja,
    /// Neispravan ulaz (prazna lozinka, slab `log_n`, nepoznat ID…).
    Neispravno(&'static str),
    /// Postoje nerazriješeni sukobi (npr. prije rotacije).
    ImaSukoba,
    /// Paket iz sefa uređaja (SEG 13) ne otvara fajlove trezora: ključ je
    /// rotiran na drugom uređaju ili je paket tuđ ⇒ traži se lozinka.
    KljucZastario,
    Age(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------- pomoćno

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn short(tag_hex: &str) -> String {
    tag_hex.chars().take(16).collect()
}

fn hmac(key: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC prima ključ bilo koje dužine");
    m.update(label);
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn hmac_verify(key: &[u8], label: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC prima ključ bilo koje dužine");
    m.update(label);
    for p in parts {
        m.update(p);
    }
    m.verify_slice(tag).is_ok()
}

/// Atomičan upis: privremeni fajl u `.mdai-vault/tmp/`, pa `rename` (spec R6).
fn atomic_write(vault_dir: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_dir = vault_dir.join(DIR).join(TMP);
    fs::create_dir_all(&tmp_dir)?;
    let tmp = tmp_dir.join(format!("{}.part", to_hex(&random_bytes::<8>())));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, target)?;
    Ok(())
}

fn age_encrypt(recipients: &[&dyn age::Recipient], plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = age::Encryptor::with_recipients(recipients.iter().copied())
        .map_err(|e| Error::Age(e.to_string()))?;
    let mut out = Vec::with_capacity(plaintext.len() + 512);
    let mut w = enc.wrap_output(&mut out)?;
    w.write_all(plaintext)?;
    w.finish()?;
    Ok(out)
}

fn age_encrypt_passphrase(password: &str, log_n: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut r = age::scrypt::Recipient::new(SecretString::from(password.to_owned()));
    r.set_work_factor(log_n);
    age_encrypt(&[&r as &dyn age::Recipient], plaintext)
}

enum AgeFail {
    NoKey,
    Broken,
}

fn age_decrypt(identities: &[&dyn age::Identity], bytes: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, AgeFail> {
    let d = age::Decryptor::new_buffered(bytes).map_err(|_| AgeFail::Broken)?;
    let mut r = d.decrypt(identities.iter().copied()).map_err(|e| match e {
        age::DecryptError::NoMatchingKeys => AgeFail::NoKey,
        _ => AgeFail::Broken,
    })?;
    let mut out = Zeroizing::new(Vec::new());
    r.read_to_end(&mut out).map_err(|_| AgeFail::Broken)?;
    Ok(out)
}

// ---------------------------------------------------------------- 24 riječi (spec R19)

/// 32 bajta tajnog X25519 ključa ⇒ 24 BIP-39 riječi. Samo kodiranje, ⛔ PBKDF2/HKDF.
pub fn key_bytes_to_words(bytes: &[u8; 32]) -> Zeroizing<String> {
    let m = bip39::Mnemonic::from_entropy(bytes).expect("32 bajta je ispravna BIP-39 entropija");
    Zeroizing::new(m.to_string())
}

/// 24 riječi ⇒ 32 bajta. Provjerava BIP-39 kontrolni zbir.
pub fn words_to_key_bytes(words: &str) -> Result<Zeroizing<[u8; 32]>> {
    let norm: String = words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &norm)
        .map_err(|_| Error::PogresneRijeci)?;
    let (arr, len) = m.to_entropy_array();
    if len != 32 {
        return Err(Error::PogresneRijeci);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&arr[..32]);
    Ok(out)
}

/// 32 bajta ⇒ `AGE-SECRET-KEY-1…` (bech32, kao `age-keygen`). Za otvaranje bez mdai-ja.
pub fn key_bytes_to_age_secret(bytes: &[u8; 32]) -> Zeroizing<String> {
    let hrp = bech32::Hrp::parse(AGE_SECRET_HRP).expect("HRP je ispravan");
    let s = bech32::encode::<bech32::Bech32>(hrp, bytes).expect("dužina je ispravna");
    Zeroizing::new(s.to_uppercase())
}

/// 24 riječi ⇒ `AGE-SECRET-KEY-1…`.
pub fn words_to_age_secret(words: &str) -> Result<Zeroizing<String>> {
    let b = words_to_key_bytes(words)?;
    Ok(key_bytes_to_age_secret(&b))
}

fn words_to_identity(words: &str) -> Result<age::x25519::Identity> {
    let s = words_to_age_secret(words)?;
    age::x25519::Identity::from_str(&s).map_err(|_| Error::PogresneRijeci)
}

// ---------------------------------------------------------------- paket ključeva

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
struct OldKey {
    gen: u32,
    identity: String,
    mac_key: String,
}

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
struct Bundle {
    format: u32,
    vault_id: String,
    gen: u32,
    identity: String,
    mac_key: String,
    recovery_recipient: String,
    #[serde(default)]
    previous: Vec<OldKey>,
}

struct Keys {
    gen: u32,
    identity: age::x25519::Identity,
    mac_key: Zeroizing<Vec<u8>>,
}

fn parse_keys(gen: u32, identity: &str, mac_key: &str) -> Result<Keys> {
    let identity = age::x25519::Identity::from_str(identity).map_err(|_| Error::Neispravno("identity"))?;
    let mac_key = Zeroizing::new(from_hex(mac_key).ok_or(Error::Neispravno("mac_key"))?);
    if mac_key.len() != 32 {
        return Err(Error::Neispravno("mac_key"));
    }
    Ok(Keys { gen, identity, mac_key })
}

// ---------------------------------------------------------------- opcije

#[derive(Clone, Copy, Debug)]
pub struct CreateOptions {
    pub scrypt_log_n: u8,
}

impl CreateOptions {
    /// `log_n = MIN_LOG_N` (18). Aplikacija može dati veći (ono što `age` izabere ≈ 1 s).
    pub fn standard() -> Self {
        CreateOptions { scrypt_log_n: MIN_LOG_N }
    }
    /// ⚠️ Samo za testove: slab scrypt da testovi traju sekunde.
    #[doc(hidden)]
    pub fn insecure_fast_for_tests() -> Self {
        CreateOptions { scrypt_log_n: 10 }
    }
}

// ---------------------------------------------------------------- zaglavlje fajla

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Note,
    Asset,
    Dir,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub v: u32,
    pub vault: String,
    pub gen: u32,
    pub id: String,
    pub kind: Kind,
    pub path: String,
    pub rev: u64,
    pub anc: Vec<String>,
    pub dev: String,
    pub deleted: bool,
    pub len: u64,
}

/// Sastavi plaintext fajla (spec §2). Javno da bi testovi mogli praviti podmetnute fajlove.
pub fn build_plaintext(header: &Header, body: &[u8], mac_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let json = serde_json::to_vec(header).expect("serijalizacija zaglavlja");
    if json.len() > HEADER_LEN {
        return Err(Error::PredugackaPutanja);
    }
    let mut region = vec![0u8; HEADER_LEN];
    region[..json.len()].copy_from_slice(&json);
    let htag = hmac(mac_key, LABEL_HEADER, &[&region]);
    let unpadded = HEADER_LEN + TAG_LEN + body.len() + TAG_LEN;
    let total = unpadded.div_ceil(BUCKET) * BUCKET;
    let pad = total - unpadded;
    let mut pt = Zeroizing::new(Vec::with_capacity(total));
    pt.extend_from_slice(&region);
    pt.extend_from_slice(&htag);
    pt.extend_from_slice(body);
    let n = pt.len() + pad;
    pt.resize(n, 0u8);
    let tag = hmac(mac_key, LABEL_FILE, &[&pt]);
    pt.extend_from_slice(&tag);
    Ok(pt)
}

// ---------------------------------------------------------------- lokalno stanje uređaja

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Known {
    pub rev: u64,
    pub tag: String,
    pub anc: Vec<String>,
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OwnWrite {
    pub rev: u64,
    pub tag: String,
    pub path: String,
    pub kind: Kind,
    pub deleted: bool,
    pub body: Vec<u8>,
}

impl Drop for OwnWrite {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// Stanje jednog uređaja. Živi VAN foldera trezora; na disk samo šifrovano (spec §2, R11).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalState {
    pub dev: String,
    pub vault_id: Option<String>,
    pub known: BTreeMap<String, Known>,
    pub own: BTreeMap<String, OwnWrite>,
}

impl LocalState {
    pub fn new() -> Self {
        LocalState {
            dev: to_hex(&random_bytes::<8>()),
            vault_id: None,
            known: BTreeMap::new(),
            own: BTreeMap::new(),
        }
    }
}

impl Default for LocalState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- rezultat skeniranja

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Isto kao zadnje viđeno.
    Isto,
    /// Prvi put viđen ID.
    Novo,
    /// Novija verzija koja nastavlja ono što znamo.
    Napred,
    /// `rev` manji od poznatog: vraćena starija verzija (R9).
    Vraceno { disk_rev: u64, known_rev: u64 },
    /// Verzija na disku ne nastavlja moj zadnji upis (R3), ili ista `rev` sa drugim sadržajem.
    Racva { moja_dostupna: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// Nije za naš ključ (podmetnut ili iz drugog trezora).
    Tudj,
    /// Odsječen ili oštećen `age` fajl (prekinut prenos, R5).
    Nepotpun,
    /// Dešifruje se, ali HMAC ne prolazi ili je drugi trezor (R8).
    Neautentican,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub disk_name: String,
    pub header: Header,
    pub tag: String,
    pub body: Zeroizing<Vec<u8>>,
    pub status: Status,
    /// Ime na disku ne počinje ID-om iz zaglavlja (premješten/zamijenjen fajl).
    pub ime_ne_odgovara: bool,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    /// Po jedan unos za svaki ID koji ima tačno jedan ispravan fajl.
    pub entries: Vec<Entry>,
    /// ID ⇒ svi ispravni fajlovi sa tim ID-om, kad ih je više (kopije provajdera, R2).
    pub conflicts: BTreeMap<String, Vec<Entry>>,
    /// Fajlovi koji se ne prikazuju kao bilješke, uz razlog.
    pub problems: Vec<(String, Problem)>,
    /// Poznati ID-ovi kojih nema na disku, bez nadgrobnog kamena (R4).
    pub missing: Vec<String>,
}

impl ScanReport {
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.header.id == id)
    }
    pub fn problem(&self, disk_name: &str) -> Option<&Problem> {
        self.problems.iter().find(|(n, _)| n == disk_name).map(|(_, p)| p)
    }
}

// ---------------------------------------------------------------- trezor

pub struct Created {
    pub vault: Vault,
    /// Prikazati jednom; korisnik upiše 3 nasumične riječi prije kraja (UI).
    pub recovery_words: Zeroizing<String>,
}

/// Otključan trezor.
pub struct Vault {
    dir: PathBuf,
    bundle: Bundle,
    current: Keys,
    previous: Vec<Keys>,
    recovery: age::x25519::Recipient,
}

#[derive(Serialize, Deserialize)]
struct VaultJson {
    format: u32,
    vault_id: String,
}

fn read_vault_json_format(dir: &Path) -> Result<(u64, String)> {
    let p = dir.join(DIR).join(VAULT_JSON);
    let raw = fs::read(&p).map_err(|_| Error::NijeTrezor)?;
    let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| Error::NijeTrezor)?;
    let format = v.get("format").and_then(|x| x.as_u64()).ok_or(Error::NijeTrezor)?;
    let id = v.get("vault_id").and_then(|x| x.as_str()).ok_or(Error::NijeTrezor)?.to_owned();
    // Sve ostalo (npr. "recipients", "kdf", "cipher") se namjerno ignoriše (R7, Q8).
    Ok((format, id))
}

fn new_recovery_key() -> (Zeroizing<[u8; 32]>, age::x25519::Identity) {
    let bytes = Zeroizing::new(random_bytes::<32>());
    let id = age::x25519::Identity::from_str(&key_bytes_to_age_secret(&bytes)).expect("ispravan ključ");
    (bytes, id)
}

impl Vault {
    fn from_bundle(dir: &Path, bundle: Bundle) -> Result<Self> {
        if bundle.format != FORMAT {
            return Err(Error::NepoznatFormat(bundle.format as u64));
        }
        let current = parse_keys(bundle.gen, &bundle.identity, &bundle.mac_key)?;
        let previous = bundle
            .previous
            .iter()
            .map(|o| parse_keys(o.gen, &o.identity, &o.mac_key))
            .collect::<Result<Vec<_>>>()?;
        let recovery = age::x25519::Recipient::from_str(&bundle.recovery_recipient)
            .map_err(|_| Error::Neispravno("recovery_recipient"))?;
        Ok(Vault { dir: dir.to_owned(), bundle, current, previous, recovery })
    }

    fn check_vault_json(dir: &Path, bundle: &Bundle) -> Result<()> {
        let (format, id) = read_vault_json_format(dir)?;
        if format != FORMAT as u64 {
            return Err(Error::NepoznatFormat(format));
        }
        if id != bundle.vault_id {
            return Err(Error::DrugiTrezor);
        }
        Ok(())
    }

    fn write_keyfiles(&self, password: Option<&str>, opts: CreateOptions) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(&self.bundle).expect("paket"));
        if let Some(pw) = password {
            let p = age_encrypt_passphrase(pw, opts.scrypt_log_n, &json)?;
            atomic_write(&self.dir, &self.dir.join(DIR).join(KEY_PASS), &p)?;
        }
        let r = age_encrypt(&[&self.recovery as &dyn age::Recipient], &json)?;
        atomic_write(&self.dir, &self.dir.join(DIR).join(KEY_RECOVERY), &r)?;
        Ok(())
    }

    /// Tok 1: kreiranje. Folder mora biti prazan ili ne postojati.
    pub fn create(dir: &Path, password: &str, opts: CreateOptions) -> Result<Created> {
        if password.is_empty() {
            return Err(Error::Neispravno("prazna lozinka"));
        }
        if opts.scrypt_log_n < 10 {
            return Err(Error::Neispravno("scrypt_log_n"));
        }
        if dir.exists() && fs::read_dir(dir)?.next().is_some() {
            return Err(Error::VecPostoji);
        }
        fs::create_dir_all(dir.join(DIR).join(TMP))?;
        let identity = age::x25519::Identity::generate();
        let (rec_bytes, rec_id) = new_recovery_key();
        let words = key_bytes_to_words(&rec_bytes);
        let bundle = Bundle {
            format: FORMAT,
            vault_id: to_hex(&random_bytes::<16>()),
            gen: 0,
            identity: identity.to_string().expose_secret().to_owned(),
            mac_key: to_hex(&Zeroizing::new(random_bytes::<32>())[..]),
            recovery_recipient: rec_id.to_public().to_string(),
            previous: vec![],
        };
        let vj = serde_json::to_vec(&VaultJson { format: FORMAT, vault_id: bundle.vault_id.clone() }).unwrap();
        atomic_write(dir, &dir.join(DIR).join(VAULT_JSON), &vj)?;
        let vault = Vault::from_bundle(dir, bundle)?;
        vault.write_keyfiles(Some(password), opts)?;
        Ok(Created { vault, recovery_words: words })
    }

    /// Tok 2: otključavanje lozinkom.
    pub fn unlock(dir: &Path, password: &str) -> Result<Self> {
        let (format, _) = read_vault_json_format(dir)?;
        if format != FORMAT as u64 {
            return Err(Error::NepoznatFormat(format));
        }
        let raw = fs::read(dir.join(DIR).join(KEY_PASS))?;
        let id = age::scrypt::Identity::new(SecretString::from(password.to_owned()));
        let json = age_decrypt(&[&id as &dyn age::Identity], &raw).map_err(|_| Error::PogresnaLozinka)?;
        let bundle: Bundle = serde_json::from_slice(&json).map_err(|_| Error::PogresnaLozinka)?;
        Self::check_vault_json(dir, &bundle)?;
        Vault::from_bundle(dir, bundle)
    }

    /// Tok 8 (prvi dio): otključavanje riječima, uz provjeru da paket ovjerava bar jedan
    /// postojeći fajl (inače je `key.recovery.age` mogao biti podmetnut).
    pub fn unlock_with_recovery(dir: &Path, words: &str) -> Result<Self> {
        let (format, _) = read_vault_json_format(dir)?;
        if format != FORMAT as u64 {
            return Err(Error::NepoznatFormat(format));
        }
        let rec = words_to_identity(words)?;
        let raw = fs::read(dir.join(DIR).join(KEY_RECOVERY))?;
        let json = age_decrypt(&[&rec as &dyn age::Identity], &raw).map_err(|_| Error::PogresneRijeci)?;
        let bundle: Bundle = serde_json::from_slice(&json).map_err(|_| Error::PogresneRijeci)?;
        if bundle.recovery_recipient != rec.to_public().to_string() {
            return Err(Error::OporavakNeprovjeren);
        }
        Self::check_vault_json(dir, &bundle)?;
        let v = Vault::from_bundle(dir, bundle)?;
        let mut verified = false;
        for (_, bytes) in v.list_files()? {
            if v.decode(&bytes).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(Error::OporavakNeprovjeren);
        }
        Ok(v)
    }

    /// SEG 13 — `vault_id` iz `vault.json`, BEZ otključavanja (ime stavke u
    /// sefu uređaja). Nije tajna.
    pub fn peek_vault_id(dir: &Path) -> Result<String> {
        let (format, id) = read_vault_json_format(dir)?;
        if format != FORMAT as u64 {
            return Err(Error::NepoznatFormat(format));
        }
        Ok(id)
    }

    /// SEG 13 — paket ključeva za sef OVOG uređaja (OS keychain). TAJNA:
    /// ko ga ima, čita trezor bez lozinke. ⛔ Na disk, ⛔ u log, ⛔ u oblak.
    pub fn key_bundle(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(serde_json::to_vec(&self.bundle).expect("paket"))
    }

    /// SEG 13 — otključavanje paketom iz sefa uređaja. Zastario paket (ključ
    /// rotiran drugdje: neki fajl je šifrovan ključem kog paket nema) ili
    /// paket koji ne otvara nijedan postojeći fajl ⇒ [`Error::KljucZastario`].
    pub fn unlock_with_bundle(dir: &Path, bundle_json: &[u8]) -> Result<Self> {
        let (format, _) = read_vault_json_format(dir)?;
        if format != FORMAT as u64 {
            return Err(Error::NepoznatFormat(format));
        }
        let bundle: Bundle = serde_json::from_slice(bundle_json).map_err(|_| Error::KljucZastario)?;
        Self::check_vault_json(dir, &bundle)?;
        let v = Vault::from_bundle(dir, bundle)?;
        let (mut ima, mut otvara) = (false, false);
        for (_, bytes) in v.list_files()? {
            ima = true;
            match v.decode(&bytes) {
                Ok(_) => otvara = true,
                Err(Problem::Tudj) => return Err(Error::KljucZastario),
                Err(_) => {}
            }
        }
        if ima && !otvara {
            return Err(Error::KljucZastario);
        }
        Ok(v)
    }

    pub fn vault_id(&self) -> &str {
        &self.bundle.vault_id
    }
    pub fn generation(&self) -> u32 {
        self.bundle.gen
    }
    /// Javni ključ trezora. Nije tajna, ali se ⛔ upisuje u oblak (spec R8 varijanta B).
    pub fn vault_recipient(&self) -> String {
        self.current.identity.to_public().to_string()
    }
    pub fn recovery_recipient(&self) -> String {
        self.bundle.recovery_recipient.clone()
    }
    #[doc(hidden)]
    pub fn mac_key_for_tests(&self) -> Vec<u8> {
        self.current.mac_key.to_vec()
    }

    /// Tok 7: promjena lozinke. Fajlovi i `key.recovery.age` se ne diraju.
    pub fn change_password(&self, new_password: &str, opts: CreateOptions) -> Result<()> {
        if new_password.is_empty() {
            return Err(Error::Neispravno("prazna lozinka"));
        }
        let json = Zeroizing::new(serde_json::to_vec(&self.bundle).expect("paket"));
        let p = age_encrypt_passphrase(new_password, opts.scrypt_log_n, &json)?;
        atomic_write(&self.dir, &self.dir.join(DIR).join(KEY_PASS), &p)
    }

    /// Tok 9: izgubljene riječi. Nove riječi + novi `key.recovery.age` (+ `key.pass.age`
    /// jer se paket mijenja). ⚠️ Stari fajlovi ostaju čitljivi starim riječima do rotacije.
    pub fn new_recovery(&mut self, password: &str, opts: CreateOptions) -> Result<Zeroizing<String>> {
        let (bytes, id) = new_recovery_key();
        self.bundle.recovery_recipient = id.to_public().to_string();
        self.recovery = id.to_public();
        self.write_keyfiles(Some(password), opts)?;
        Ok(key_bytes_to_words(&bytes))
    }

    /// Tok 10: novi ključ trezora. Novi ključ, MAC ključ i riječi; svi fajlovi se prepisuju.
    pub fn rotate(&mut self, local: &mut LocalState, password: &str, opts: CreateOptions) -> Result<Zeroizing<String>> {
        let report = self.scan(local)?;
        if !report.conflicts.is_empty() {
            return Err(Error::ImaSukoba);
        }
        let old = OldKey {
            gen: self.bundle.gen,
            identity: self.bundle.identity.clone(),
            mac_key: self.bundle.mac_key.clone(),
        };
        let identity = age::x25519::Identity::generate();
        let (rec_bytes, rec_id) = new_recovery_key();
        self.bundle.previous.push(old);
        self.bundle.gen += 1;
        self.bundle.identity = identity.to_string().expose_secret().to_owned();
        self.bundle.mac_key = to_hex(&Zeroizing::new(random_bytes::<32>())[..]);
        self.bundle.recovery_recipient = rec_id.to_public().to_string();
        // Paket sa novim ključem se upisuje PRIJE prepisa, da prekid ne ostavi fajlove
        // koje nijedan paket ne otvara.
        let b = self.bundle.clone();
        *self = Vault::from_bundle(&self.dir, b)?;
        self.write_keyfiles(Some(password), opts)?;
        for e in report.entries {
            self.write_inner(local, &e.header.id, e.header.kind, &e.header.path, &e.body, e.header.deleted, None)?;
        }
        Ok(key_bytes_to_words(&rec_bytes))
    }

    fn file_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.age"))
    }

    fn all_keys(&self) -> impl Iterator<Item = &Keys> {
        iter::once(&self.current).chain(self.previous.iter())
    }

    /// Dešifruj i ovjeri jedan fajl. Vraća (zaglavlje, tag, tijelo).
    fn decode(&self, bytes: &[u8]) -> std::result::Result<(Header, String, Zeroizing<Vec<u8>>), Problem> {
        let ids: Vec<&dyn age::Identity> = self.all_keys().map(|k| &k.identity as &dyn age::Identity).collect();
        let pt = age_decrypt(&ids, bytes).map_err(|e| match e {
            AgeFail::NoKey => Problem::Tudj,
            AgeFail::Broken => Problem::Nepotpun,
        })?;
        if pt.len() < HEADER_LEN + 2 * TAG_LEN || !pt.len().is_multiple_of(BUCKET) {
            return Err(Problem::Neautentican);
        }
        let region = &pt[..HEADER_LEN];
        let end = region.iter().position(|&b| b == 0).unwrap_or(HEADER_LEN);
        let header: Header = serde_json::from_slice(&region[..end]).map_err(|_| Problem::Neautentican)?;
        let keys = self.all_keys().find(|k| k.gen == header.gen).ok_or(Problem::Neautentican)?;
        let htag = &pt[HEADER_LEN..HEADER_LEN + TAG_LEN];
        if !hmac_verify(&keys.mac_key, LABEL_HEADER, &[region], htag) {
            return Err(Problem::Neautentican);
        }
        let split = pt.len() - TAG_LEN;
        if !hmac_verify(&keys.mac_key, LABEL_FILE, &[&pt[..split]], &pt[split..]) {
            return Err(Problem::Neautentican);
        }
        if header.v != FORMAT || header.vault != self.bundle.vault_id {
            return Err(Problem::Neautentican);
        }
        let start = HEADER_LEN + TAG_LEN;
        let len = header.len as usize;
        if start + len > split || pt[start + len..split].iter().any(|&b| b != 0) {
            return Err(Problem::Neautentican);
        }
        let body = Zeroizing::new(pt[start..start + len].to_vec());
        Ok((header, to_hex(&pt[split..]), body))
    }

    fn list_files(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut out = vec![];
        for e in fs::read_dir(&self.dir)? {
            let e = e?;
            if !e.file_type()?.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".age") || name.starts_with('.') {
                continue;
            }
            out.push((name, fs::read(e.path())?));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_inner(
        &self,
        local: &mut LocalState,
        id: &str,
        kind: Kind,
        path: &str,
        body: &[u8],
        deleted: bool,
        extra_anc: Option<Vec<String>>,
    ) -> Result<String> {
        let (rev, anc) = match local.known.get(id) {
            Some(k) => {
                let mut anc = vec![short(&k.tag)];
                if let Some(extra) = &extra_anc {
                    for a in extra {
                        if !anc.contains(a) {
                            anc.push(a.clone());
                        }
                    }
                }
                anc.extend(k.anc.iter().cloned());
                anc.dedup();
                anc.truncate(MAX_ANC);
                (k.rev + 1, anc)
            }
            None => (1, vec![]),
        };
        let header = Header {
            v: FORMAT,
            vault: self.bundle.vault_id.clone(),
            gen: self.current.gen,
            id: id.to_owned(),
            kind,
            path: path.to_owned(),
            rev,
            anc: anc.clone(),
            dev: local.dev.clone(),
            deleted,
            len: body.len() as u64,
        };
        let pt = build_plaintext(&header, body, &self.current.mac_key)?;
        let tag = to_hex(&pt[pt.len() - TAG_LEN..]);
        let ct = age_encrypt(
            &[&self.current.identity.to_public() as &dyn age::Recipient, &self.recovery as &dyn age::Recipient],
            &pt,
        )?;
        atomic_write(&self.dir, &self.file_path(id), &ct)?;
        local.vault_id = Some(self.bundle.vault_id.clone());
        local.known.insert(id.to_owned(), Known { rev, tag: tag.clone(), anc, deleted });
        local.own.insert(
            id.to_owned(),
            OwnWrite { rev, tag: tag.clone(), path: path.to_owned(), kind, deleted, body: body.to_vec() },
        );
        Ok(tag)
    }

    /// Tok 3: novi fajl. Vraća ID.
    pub fn create_file(&self, local: &mut LocalState, kind: Kind, path: &str, body: &[u8]) -> Result<String> {
        let id = to_hex(&random_bytes::<16>());
        self.write_inner(local, &id, kind, path, body, false, None)?;
        Ok(id)
    }

    /// Tok 3: izmjena postojećeg fajla (ID mora biti poznat ovom uređaju).
    pub fn write_file(&self, local: &mut LocalState, id: &str, path: &str, body: &[u8]) -> Result<()> {
        let kind = match local.own.get(id) {
            Some(o) => o.kind,
            None => {
                let (h, _, _) = self.read_raw(id)?;
                h.kind
            }
        };
        if !local.known.contains_key(id) {
            return Err(Error::Neispravno("nepoznat ID"));
        }
        self.write_inner(local, id, kind, path, body, false, None).map(|_| ())
    }

    /// Tok 6: brisanje = nadgrobni kamen.
    pub fn delete_file(&self, local: &mut LocalState, id: &str) -> Result<()> {
        let (h, _, _) = self.read_raw(id)?;
        if !local.known.contains_key(id) {
            return Err(Error::Neispravno("nepoznat ID"));
        }
        self.write_inner(local, id, h.kind, &h.path, &[], true, None).map(|_| ())
    }

    fn read_raw(&self, id: &str) -> Result<(Header, String, Zeroizing<Vec<u8>>)> {
        let bytes = fs::read(self.file_path(id))?;
        self.decode(&bytes).map_err(|p| Error::Age(format!("{p:?}")))
    }

    /// Tok 4: čitanje jednog fajla (bez poređenja sa lokalnim stanjem).
    pub fn read_file(&self, id: &str) -> Result<(Header, Zeroizing<Vec<u8>>)> {
        self.read_raw(id).map(|(h, _, b)| (h, b))
    }

    /// Tok 4: skeniranje cijelog trezora i poređenje sa lokalnim stanjem.
    /// Ažurira `local` samo za sigurne slučajeve (Isto, Novo, Napred).
    pub fn scan(&self, local: &mut LocalState) -> Result<ScanReport> {
        let mut report = ScanReport::default();
        let mut by_id: HashMap<String, Vec<Entry>> = HashMap::new();
        for (name, bytes) in self.list_files()? {
            match self.decode(&bytes) {
                Err(p) => report.problems.push((name, p)),
                Ok((header, tag, body)) => {
                    let ime_ne_odgovara = !name.starts_with(&header.id);
                    let status = classify(local, &header, &tag);
                    by_id.entry(header.id.clone()).or_default().push(Entry {
                        disk_name: name,
                        header,
                        tag,
                        body,
                        status,
                        ime_ne_odgovara,
                    });
                }
            }
        }
        for (id, known) in &local.known {
            if !by_id.contains_key(id) && !known.deleted {
                report.missing.push(id.clone());
            }
        }
        let mut ids: Vec<_> = by_id.keys().cloned().collect();
        ids.sort();
        for id in ids {
            let mut v = by_id.remove(&id).unwrap();
            if v.len() > 1 {
                report.conflicts.insert(id, v);
                continue;
            }
            let e = v.pop().unwrap();
            if matches!(e.status, Status::Isto | Status::Novo | Status::Napred) {
                accept(local, &e);
            }
            report.entries.push(e);
        }
        Ok(report)
    }

    /// Tok 5 (račva): moju izgubljenu verziju upiši kao NOVU bilješku, pa prihvati disk.
    /// Vraća ID nove bilješke (ili `None` ako je moj izgubljeni upis bio brisanje).
    pub fn resolve_fork(&self, local: &mut LocalState, report: &ScanReport, id: &str) -> Result<Option<String>> {
        let e = report.entry(id).ok_or(Error::Neispravno("nema unosa"))?;
        let own = local.own.remove(id);
        accept(local, e);
        match own {
            Some(o) if !o.deleted => {
                let path = conflict_path(&o.path, &local.dev);
                let body = o.body.clone();
                let kind = o.kind;
                self.create_file(local, kind, &path, &body).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Tok 5 (kopije provajdera): korisnik je izabrao/spojio sadržaj; upiši novu verziju
    /// čiji preci uključuju sve kopije. Kopije se NE brišu ovdje.
    pub fn resolve_conflict(&self, local: &mut LocalState, report: &ScanReport, id: &str, path: &str, body: &[u8]) -> Result<()> {
        let variants = report.conflicts.get(id).ok_or(Error::Neispravno("nema sukoba"))?;
        let max = variants.iter().max_by_key(|e| e.header.rev).unwrap();
        let kind = max.header.kind;
        let extra: Vec<String> = variants.iter().map(|e| short(&e.tag)).collect();
        accept(local, max);
        local.own.remove(id);
        self.write_inner(local, id, kind, path, body, false, Some(extra)).map(|_| ())
    }

    /// Ukloni kopiju provajdera, ali samo ako je njen sadržaj već u lancu predaka
    /// kanonskog fajla (tj. korisnik je sukob riješio). Inače odbij.
    pub fn remove_copy(&self, disk_name: &str) -> Result<()> {
        let p = self.dir.join(disk_name);
        let copy = self.decode(&fs::read(&p)?).map_err(|_| Error::Neispravno("kopija nije ispravna"))?;
        if disk_name == format!("{}.age", copy.0.id) {
            return Err(Error::Neispravno("ovo je kanonski fajl"));
        }
        let canon = self.read_raw(&copy.0.id)?;
        if !canon.0.anc.contains(&short(&copy.1)) {
            return Err(Error::Neispravno("sukob nije riješen"));
        }
        fs::remove_file(p)?;
        Ok(())
    }

    /// Lokalno stanje na disk, šifrovano ključem trezora (R11). Putanja mora biti VAN trezora.
    pub fn save_local_state(&self, local: &LocalState, path: &Path) -> Result<()> {
        if path.starts_with(&self.dir) {
            return Err(Error::Neispravno("lokalno stanje ne smije u folder trezora"));
        }
        let json = Zeroizing::new(serde_json::to_vec(local).expect("stanje"));
        let ct = age_encrypt(&[&self.current.identity.to_public() as &dyn age::Recipient], &json)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, ct)?;
        Ok(())
    }

    pub fn load_local_state(&self, path: &Path) -> Result<LocalState> {
        let raw = fs::read(path)?;
        let ids: Vec<&dyn age::Identity> = self.all_keys().map(|k| &k.identity as &dyn age::Identity).collect();
        let json = age_decrypt(&ids, &raw).map_err(|_| Error::Neispravno("lokalno stanje"))?;
        serde_json::from_slice(&json).map_err(|_| Error::Neispravno("lokalno stanje"))
    }
}

fn conflict_path(path: &str, dev: &str) -> String {
    let short_dev: String = dev.chars().take(6).collect();
    match path.rfind('.') {
        Some(i) if i > path.rfind('/').map_or(0, |s| s + 1) => {
            format!("{} (sukob {}){}", &path[..i], short_dev, &path[i..])
        }
        _ => format!("{path} (sukob {short_dev})"),
    }
}

fn classify(local: &LocalState, h: &Header, tag: &str) -> Status {
    let known = local.known.get(&h.id);
    if let Some(k) = known {
        if h.rev < k.rev {
            return Status::Vraceno { disk_rev: h.rev, known_rev: k.rev };
        }
    }
    if let Some(o) = local.own.get(&h.id) {
        let confirmed = o.tag == tag || h.anc.contains(&short(&o.tag));
        if !confirmed {
            return Status::Racva { moja_dostupna: true };
        }
    }
    match known {
        None => Status::Novo,
        Some(k) if k.tag == tag => Status::Isto,
        Some(k) if h.rev > k.rev => Status::Napred,
        Some(_) => Status::Racva { moja_dostupna: false },
    }
}

fn accept(local: &mut LocalState, e: &Entry) {
    local.known.insert(
        e.header.id.clone(),
        Known { rev: e.header.rev, tag: e.tag.clone(), anc: e.header.anc.clone(), deleted: e.header.deleted },
    );
    if let Some(o) = local.own.get(&e.header.id) {
        if o.tag == e.tag || e.header.anc.contains(&short(&o.tag)) {
            local.own.remove(&e.header.id);
        }
    }
}
