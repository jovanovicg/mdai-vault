# Format trezora v1 — specifikacija

## Odluke v1

| # | odluka | gdje u spec-u |
|---|---|---|
| 1 | HMAC-SHA256 uz `age` za autentičnost fajlova | §2, R8, Q6 |
| 2 | 24 riječi = BIP-39 zapis nasumičnog ključa, bez PBKDF2 | R19, §3a |
| 3 | ime unutar istog `age` fajla, bez pratećeg fajla | §2, R1, R5 |
| 4 | brisanje = nadgrobni kamen 4 KiB, čišćenje tek u v2 | R4, §5.6 |
| 5 | svaki fajl za dva primaoca (ključ trezora + ključ za oporavak) | §2, Q4 |
| 6 | R15 i R17 su van formata; prateći tekstovi se vode odvojeno | R15, R17 |
| 7 | `age` **0.12.1** | Q16, §7 |
| 8 | oporavak riječima se odbija u praznom trezoru | §5.8 |
| 9 | testovi se ponavljaju poslije prelaska na 0.12.1 | §7 |

Oznake: `[NEPROVJERENO]` tvrdnja o tuđem proizvodu bez citata · `[IZMJERENO]` uz komandu · `BLOKER` granica blokira rješenje · **odluka** / **otvoreno**.

---

## 0. Jedna strana

**Napravljeno:** raspored na disku bez ijednog zajedničkog fajla koji se mijenja; ime, putanja, verzija i ID su **u istom `age` fajlu** sa sadržajem (nema pratećeg fajla u oblaku, R1 i R5 nestaju); autentičnost sa **HMAC-SHA256** ključem trezora (nasumičan ključ, ⛔ izveden); primaoci se **nikad** ne čitaju iz oblaka (R7); brojač verzije + lanac predaka zatvara rollback i tihi gubitak kod offline sukoba (R3, R9); 24 riječi = **BIP-39 kodiranje** 32 bajta nasumičnog X25519 ključa, ⛔ bez PBKDF2/HKDF (R19).

**Nije napravljeno / otvoreno:** ponašanje provajdera (S3) je ⛔ neizmjereno; scrypt cijena na telefonu (S4); S8 (gotov format) nije rađen.

**BLOKER:** nema. HMAC-SHA256 van `age` je odobren (odluka 1).

---

## 1. Model prijetnje

| akter | jedna rečenica | štitimo? |
|---|---|---|
| provajder **čita** | vidi samo nasumična imena, broj fajlova, veličinu zaokruženu na 4 KiB, vrijeme izmjene i da je to mdai trezor; ne vidi sadržaj, ime, putanju ni strukturu foldera | **da** (osim navedenog) |
| provajder **piše** (ili malver na drugom uređaju, deljen link) | može brisati, vraćati stare verzije, dodavati i premještati fajlove; ⛔ ne može napraviti fajl koji mdai prihvati kao autentičan, a svaku od tih radnji mdai **prijavi** umjesto da je tiho prikaže | **djelimično**: otkrivanje da, sprečavanje brisanja ⛔ ne (podaci su kod njega) |
| kradljivac **zaključanog** laptopa | dobija ono što i provajder plus lokalni keš, koji je šifrovan ključem trezora; pogađa lozinku offline protiv scrypt-a | **da**, koliko je jaka lozinka |
| kradljivac **otključanog** laptopa / malver na njemu | vidi sve što i korisnik | **ne** |
| neko sa **bekapom** (Time Machine, File History, iCloud backup) | isto kao provajder koji čita, plus sve stare verzije `key.pass.age` | **da**, koliko je jaka lozinka (stara lozinka važi za stare kopije, §5.7) |

**Eksplicitno ⛔ ne štitimo (Q5):** otključan uređaj; tekst koji korisnik sam pošalje AI provajderu, izveze ili odštampa; metapodatke iz reda „provajder čita“; dostupnost (provajder može sve izbrisati); slabu lozinku; 24 riječi koje je neko drugi vidio; JS/WebView memoriju (Q12); obrazac rada (vrijeme izmjena).

---

## 2. Raspored na disku

```
<trezor>/                         bilo koji folder; sinhronizuje ga korisnikov oblak, ⛔ mdai
  .mdai-vault/
    vault.json                    marker, javno: {"format":1,"vault_id":"<32 hex>"}  ⛔ ništa drugo
    key.pass.age                  paket ključeva, age scrypt (lozinka)
    key.recovery.age              isti paket, age X25519 na ključ za oporavak (24 riječi)
    tmp/                          privremeni fajlovi pri upisu (šifrovani), čitač ih ignoriše
  3f9c…e1.age                     jedan fajl = jedna bilješka/slika/folder; ime = ID (32 hex)
  a07b…42.age
  a07b…42 (conflicted copy …).age kopija provajdera: prepoznaje se po ID-u UNUTRA (R2)
```

**Ravan raspored (R14):** svi fajlovi u korijenu, bez podfoldera; putanja postoji samo šifrovana. Prazan folder = fajl vrste `dir`.

**Bez pratećeg fajla u oblaku (R1, R5):** prijedlog iz podloge §4a (mali prateći fajl po bilješci) je **odbačen** za oblak, jer se par može razdvojiti pri sukobu i prekinutom prenosu. Ime je u zaglavlju istog `age` fajla; brzo stablo čita samo prvi `age` STREAM komad (64 KiB) i lokalni keš van foldera.

**Paket ključeva** (plaintext unutar `key.*.age`, JSON):

| polje | značenje |
|---|---|
| `format` | `1` (ovjerena kopija; `vault.json` je samo putokaz, Q8) |
| `vault_id` | 16 nasumičnih bajtova, hex |
| `gen` | generacija ključa trezora (0, pa +1 pri svakom „novi ključ trezora“) |
| `identity` | `AGE-SECRET-KEY-1…` ključ trezora (X25519) |
| `mac_key` | 32 nasumična bajta, hex — ključ za HMAC (⛔ izveden iz ičega) |
| `recovery_recipient` | `age1…` javni ključ za oporavak (da bi se pisalo i za njega) |
| `previous` | ranije generacije `{gen, identity, mac_key}` — samo za čitanje dok traje prepis |

**Fajl u trezoru** (`<id>.age`) = `age` v1 fajl za **tačno dva** X25519 primaoca: ključ trezora i ključ za oporavak. Plaintext:

```
offset 0      ZAGLAVLJE   1024 bajta: UTF-8 JSON, dopunjen nulama do 1024   (R13: fiksno)
offset 1024   HTAG        32 bajta: HMAC-SHA256(mac_key, "mdai-vault/v1/header" || ZAGLAVLJE)
offset 1056   TIJELO      `len` bajtova sadržaja
              DOPUNA      nule, tako da (1056 + len + dopuna + 32) bude djeljivo sa 4096   (R13)
kraj − 32     TAG         HMAC-SHA256(mac_key, "mdai-vault/v1/file" || sve od offseta 0 do DOPUNE uključivo)
```

**Zaglavlje** (JSON, ključevi tačno ovi):

| polje | značenje | rupa |
|---|---|---|
| `v` | `1` | |
| `vault` | `vault_id` | podmetanje iz drugog trezora |
| `gen` | generacija ključa kojim je pisano | rotacija |
| `id` | ID fajla, 32 hex; mora biti početak imena na disku | R1, R2 |
| `kind` | `note` / `asset` / `dir` | |
| `path` | puna putanja u trezoru, npr. `Notes/2026/sastanak.md` (sadrži ime) | R1, R14 |
| `rev` | brojač verzije, raste za 1 pri svakom upisu | R9 |
| `anc` | do 16 skraćenih TAG-ova predaka (16 hex), najnoviji prvi | R3 |
| `dev` | nasumičan ID uređaja koji je pisao (⛔ ime hosta) | R8 „nije sa tvog uređaja“ |
| `deleted` | `true` = nadgrobni kamen (brisanje) | R4 |
| `len` | dužina tijela | |

Ako JSON prelazi 1024 bajta, upis se odbija (putanja ≈ do 700 bajtova). Vrijeme se ⛔ upisuje (R13, satovi se razlikuju; Odluka 8).

**Lokalno stanje uređaja** (van foldera trezora, u podacima aplikacije; R11): `{vault_id, dev, poznato: id → (rev, tag), moje: id → (rev, tag, tijelo)}`. Na disk ide **samo šifrovano** ključem trezora (`age` X25519). `moje` čuva zadnju verziju koju je **ovaj** uređaj napisao dok je ne vidi potvrđenu u oblaku; to je osnov za vraćanje izgubljenog teksta (R3).

---

## 3. Rupe R1–R19

| # | rješenje u v1 | status |
|---|---|---|
| R1 | ime je u istom `age` fajlu; nema para koji se razdvaja | **zatvoreno** |
| R2 | kopija provajdera se prepoznaje po `id` u zaglavlju (dva fajla, isti ID ⇒ sukob), ne po imenu | **zatvoreno** |
| R3 | `anc` + lokalno `moje`: ako oblak nosi verziju čiji lanac ne sadrži moj zadnji TAG, moja verzija se vraća kao nova bilješka „<ime> (sukob <uređaj>)“ | **zatvoreno u formatu**; ponašanje provajdera S3 **otvoreno** |
| R4 | brisanje = nadgrobni kamen (`deleted`, viši `rev`); fajl koji nestane bez kamena ⇒ „nestao sa diska“, ⛔ tiho; brisanje naspram izmjene ⇒ izmjena pobjeđuje (ništa se ne gubi) | **zatvoreno** |
| R5 | nema pratećeg fajla; prekinut `age` STREAM ⇒ stanje „nepotpun / čeka prenos“, prikazuje se, ⛔ sakriva i ⛔ prikazuje kao ispravan | **zatvoreno** |
| R6 | privremeni fajl u `.mdai-vault/tmp/` (šifrovan, isti volumen), pa `rename` u korijen; čitač ignoriše `tmp/` | **zatvoreno za plaintext**; smeće u oblaku pri prekidu **prihvaćeno**; šta klijenti rade sa `tmp/` `[NEPROVJERENO]` |
| R7 | primaoci = ključ trezora iz otključanog paketa + `recovery_recipient` iz paketa; `vault.json` ima samo `format` i `vault_id`, sve ostalo se ignoriše | **zatvoreno** |
| R8 | HMAC-SHA256 nasumičnim `mac_key` iz paketa nad zaglavljem i cijelim plaintextom; fajl bez ispravnog TAG-a ⇒ „neautentičan“, ⛔ prikaz kao bilješka. *(ODBAČENO 19.11.: varijanta B bez HMAC-a.)* | **zatvoreno** (odluka 1) |
| R9 | `rev` niži od poznatog ⇒ „vraćena starija verzija“, ⛔ tiho; lokalno stanje ne ide unazad bez korisnikove radnje. ⛔ ne štiti uređaj koji trezor vidi prvi put | **zatvoreno za poznate uređaje** |
| R10 | min. scrypt `log_n = 18` (age bira ≈1 s na uređaju; uzima se veće); provjera jačine lozinke (procjena entropije, ⛔ pravila simbola); tekst „promjena lozinke ne poništava staru“; radnja „novi ključ trezora“ | **djelimično**: offline pogađanje se ⛔ može spriječiti |
| R11 | lokalno stanje i keš šifrovani ključem trezora; indeksi/RAG samo u memoriji za šifrovan trezor | **zatvoreno u formatu**; primjena u aplikaciji = posao 1.3.9 |
| R12 | keš ključa u sistemskom sefu samo kao ne-sinhronizovana stavka „samo ovaj uređaj“ | **pravilo za aplikaciju** |
| R13 | zaglavlje fiksno 1024 B; plaintext zaokružen na 4 KiB (šifrat varira još desetak-stotinjak bajtova zbog nasumične „grease“ stavke koju `age` sam dodaje, izmjereno testom `s3_15_dopuna`); ⛔ `created`; ⛔ vrijeme u zaglavlju. Ostaje: broj fajlova, veličina u 4 KiB, vrijeme izmjene, marker `.mdai-vault/` | **zatvoreno koliko može** |
| R14 | ravan raspored | **zatvoreno** |
| R15 | kriterijum „Gotovo kad“ proširiti na Spotlight/Windows Search | **zahtjev za roadmap** (odluka 6) |
| R16 | podešavanja trezora su obični fajlovi u trezoru (jedan fajl po podešavanju) i dobijaju isto pravilo sukoba | **pravilo za 1.3.8/1.3.9** |
| R17 | tekst EULA/FAQ/hero | **van formata** (odluka 6) |
| R18 | provjera 3 riječi + podsjetnik posle 30 dana; ⛔ snimak ekrana | **pravilo za UI** |
| R19 | 24 riječi = BIP-39 **kodiranje** 32 bajta (256 bita + 8 bita kontrole) koji su direktno X25519 tajni ključ. ⛔ PBKDF2, ⛔ HKDF, ⛔ BIP-32. Riječi ↔ bajtovi ↔ `AGE-SECRET-KEY-1…` su tri zapisa istog broja | **zatvoreno**, gubi se §3a |

### 3a. Šta se gubi sa R19 rješenjem
- Riječi **jesu** ključ: ko ih vidi, čita trezor (nema „lozinke uz riječi“ kao BIP-39 passphrase).
- Nisu kompatibilne sa novčanicima: alat koji iz BIP-39 pravi seed (PBKDF2) dobiće drugi broj; za nas je bitna samo entropija.
- Iz riječi se ne izvodi ništa drugo; svaki novi ključ za oporavak = nove riječi.
- Dobija se: trezor se otvara **bez mdai-ja**: riječi → entropija (bilo koji BIP-39 alat) → bech32 `AGE-SECRET-KEY-1…` → `age -d -i ključ.txt <id>.age`. Rezultat je plaintext sa zaglavljem od 1024 B (§2), čitljiv bez alata.

---

## 4. Q1–Q16

| Q | odgovor | |
|---|---|---|
| Q1 | ključ trezora: `age::x25519::Identity::generate()` (OS RNG kroz `rand::OsRng`/`getrandom`); ID-ovi i `mac_key` istim RNG-om; isti Rust kod na svim platformama | **odluka** |
| Q2 | `log_n = max(18, ono što age izabere ≈ 1 s)`; čitač prihvata do age podrazumijevanog maksimuma (cilj+4) | **odluka**, broj za telefon **otvoren** (S4) |
| Q3 | §3 R19: kodiranje, ne derivacija | **odluka** |
| Q4 | da, dva primaoca (odluka 5). Ključ za oporavak je ravnopravan: čuva se van uređaja (papir); ako procuri ⇒ „novi ključ trezora“ (prepis svih fajlova) | **odluka** |
| Q5 | §1 | **odluka** |
| Q6 | HMAC-SHA256 nad zaglavljem (HTAG) i cijelim plaintextom (TAG); par ime↔sadržaj ne postoji, zamjena A↔B imena na disku ⇒ `id` ≠ ime ⇒ upozorenje | **odluka** (1) |
| Q7 | bez manifesta: `rev` + `anc` u svakom fajlu + lokalno stanje po uređaju; brisanje kamenom | **odluka**; rollback cijelog trezora za novi uređaj **otvoreno** (prihvata se) |
| Q8 | `recipients`, `kdf`, `cipher` se ne čitaju iz `vault.json`; `format` se čita samo kao putokaz, a važi `format` iz paketa. Nepoznat veći format ⇒ odbij pisanje | **odluka** |
| Q9 | izgubljene riječi, lozinka postoji: nove riječi + novi `key.recovery.age` su O(1), ali stari fajlovi ostaju čitljivi starim riječima ⇒ pravi odgovor je „novi ključ trezora“ (O(n)) | **odluka** |
| Q10 | izgubljena lozinka, riječi postoje: riječi otključaju `key.recovery.age` ⇒ provjera da paket ovjerava postojeće fajlove ⇒ nova lozinka ⇒ novi `key.pass.age`. Stari `key.pass.age` u istoriji oblaka ostaje (sa starom lozinkom) | **odluka** |
| Q11 | prikaz jednom, ⛔ međuspremnik, iOS zamagljenje ekrana, upozorenje na snimak | **pravilo za UI**, otvoreno do 1.4.1 |
| Q12 | Rust: `zeroize` na ključevima i paketu; JS string sa tekstom se ⛔ može obrisati — prihvata se i piše u §1 | **otvoreno** (recenzent) |
| Q13 | keš u sefu da, ne-sinhronizovan; bolji od slabe lozinke koju korisnik bira jer kuca često | **odluka**, Linux Secret Service **otvoreno** |
| Q14 | korpa = putanja `.trash/…` u zaglavlju (šifrovano); nacrti i indeksi šifrovani ili memorija; Git i MCP isključeni | **odluka**, primjena 1.3.9 |
| Q15 | crate se gradi ponovljivo (`cargo build --locked`); da je baš on u potpisanom `.app` recenzent ⛔ može dokazati bez naše gradnje bez potpisa | **otvoreno** |
| Q16 | `age =0.12.1` (MIT OR Apache-2.0, §7), zaključano u `Cargo.lock`; ispravke `age`-a ulaze kao sitnica u prvu sljedeću verziju. Fajl napisan nad 0.11.5 se otvara nad 0.12.1 (test `format_isti_poslije_age_0_12_1`) | **odluka** (7) |

---

## 5. Tokovi (prije → poslije)

Notacija: P = `key.pass.age`, R = `key.recovery.age`, F = fajlovi, L = lokalno stanje.

1. **Kreiranje.** Prije: prazan folder. Generiše se ključ trezora, `mac_key`, `vault_id`, ključ za oporavak (32 B ⇒ 24 riječi). Upiše se `vault.json`, P (lozinka), R (oporavak). Riječi se prikažu jednom; postupak se završava tek kad korisnik upiše 3 nasumične. Poslije: `.mdai-vault/` sa tri fajla, F prazno, L prazno.
2. **Otključavanje.** Prije: zaključano. Lozinka ⇒ P ⇒ paket; provjera `paket.format == 1`, `paket.vault_id == vault.json.vault_id` (razlika ⇒ stop); L se učita i dešifruje. Poslije: paket u memoriji (zeroize pri zaključavanju).
3. **Zapis.** Prije: fajl `id` sa `rev = n` (ili ne postoji). Novi plaintext sa `rev = n+1`, `anc = [tag_n, …]`, HTAG, TAG; šifruje se na dva primaoca u `.mdai-vault/tmp/`, pa `rename` u `<id>.age`. L: `poznato[id] = moje[id] = (n+1, tag)`. Poslije: jedan fajl promijenjen, ništa drugo.
4. **Čitanje / skeniranje.** Za svaki `*.age` u korijenu: dešifruj ⇒ provjeri HTAG, TAG, `vault`, `id` ↔ ime ⇒ uporedi sa L:
   `isto` · `novo` · `napred` (`rev` veći, a moj TAG u `anc` ili nemam svoj nepotvrđen upis) · `vraćeno` (`rev` manji) · `račva` (moj nepotvrđen upis nije u lancu) · `neautentičan` · `nepotpun` · `tuđ` (nije za naš ključ). Za poznat `id` kog nema na disku: `nestao`.
5. **Sukob (dvije kopije).** Prije: dva fajla sa istim `id` (kopija provajdera) ili `račva`. Kopija provajdera: obje verzije se prikažu, radnja „Uporedi“; korisnik bira ili spaja ⇒ zapis `rev = max+1`, `anc` sadrži oba TAG-a ⇒ tek tada korisnik može ukloniti kopiju. Račva: moja verzija iz `L.moje` se upiše kao **nova** bilješka (`id` nov, `path` „<ime> (sukob <uređaj>).md“). Poslije: ništa izgubljeno, ⛔ automatsko brisanje.
6. **Brisanje.** Prije: `rev = n`. Upiše se kamen `rev = n+1`, `deleted = true`, tijelo prazno. Fajl na disku ostaje (mali, 4 KiB). Poslije: stablo ga ne prikazuje; drugi uređaj vidi kamen, ne „nestao“. Kamenovi se u v1 ne čiste; čišćenje tek u v2 (odluka 4).
7. **Promjena lozinke.** Prije: P(stara). Paket se šifruje novom lozinkom ⇒ novi P. F i R netaknuti. Poslije: nova lozinka radi; ⚠️ stari P u istoriji oblaka/bekapa i dalje radi sa starom lozinkom (tekst u UI-ju).
8. **Gubitak lozinke.** Prije: riječi postoje. Riječi ⇒ ključ za oporavak ⇒ R ⇒ paket ⇒ **provjera**: bar jedan postojeći fajl mora proći HMAC tim paketom (inače stop: podmetnut R) ⇒ nova lozinka ⇒ novi P. Poslije: kao 7.
9. **Gubitak riječi.** Prije: lozinka postoji. Novi ključ za oporavak ⇒ nove riječi + novi R; ⚠️ fajlovi i dalje šifrovani i za stari ključ za oporavak dok se ne uradi 10. Poslije: nove riječi otvaraju **samo novo** dok se ne uradi 10; preporuka UI-ja: odmah 10.
10. **Novi ključ trezora (rotacija).** Prije: `gen = g`. Novi ključ trezora, novi `mac_key`, novi ključ za oporavak (nove riječi), `gen = g+1`, stara generacija u `previous`; svaki fajl se prepiše (`rev+1`, novi ključevi); na kraju novi P i R. Čitanje u međuvremenu radi za obje generacije. Poslije: stara lozinka, stare riječi i stari ključ ⛔ čitaju **nove** verzije; stare kopije u istoriji oblaka ostaju čitljive starim (to se ne može spriječiti).

---

## 6. Tabela slučajeva za sondu S3

„Format“ = ponašanje mdai-ja koje test u crate-u provjerava bez oblaka (simulacijom fajlova). „Oblak“ = mjeri se na pravom klijentu.

| # | slučaj | očekivano (mdai) | test u crate-u | oblak |
|---|---|---|---|---|
| S3-1 | A i B offline, oba izmijene isti fajl, oblak napravi kopiju | dva fajla, isti `id` ⇒ sukob, obje verzije vidljive | `s3_1_kopija_provajdera` | iCloud/Dropbox/OneDrive/Google `[NEPROVJERENO]` |
| S3-2 | isto, ali oblak tiho zadrži jednu (R3) | uređaj čija verzija je izgubljena vidi `račva` i vraća svoju kao novu bilješku | `s3_2_tihi_gubitak_racva` | `[NEPROVJERENO]` (koji klijent ovo radi) |
| S3-3 | B napravi više verzija dok je A offline (bez A upisa) | `napred`, ⛔ sukob | `s3_3_vise_verzija_napred` | — |
| S3-4 | A briše, B mijenja (R4) | izmjena pobjeđuje; ništa izgubljeno | `s3_4_brisanje_naspram_izmjene` | `[NEPROVJERENO]` |
| S3-5 | fajl nestane bez kamena (klijent/korisnik obrisao) | `nestao`, upozorenje | `s3_5_nestao_bez_kamena` | — |
| S3-6 | prekinut prenos (fajl odsječen) | `nepotpun`, ⛔ prikaz kao ispravan | `s3_6_prekinut_prenos` | da li klijent ikad izloži pola fajla `[NEPROVJERENO]` |
| S3-7 | oblak vrati stariju verziju (R9) | `vraćeno`, upozorenje | `s3_7_rollback` | — |
| S3-8 | podmetnut fajl šifrovan za ključ trezora, bez ključa za MAC (R8) | `neautentičan` | `s3_8_podmetnut_bez_maca` | — |
| S3-9 | podmetnut fajl za tuđ ključ | `tuđ` | `s3_9_podmetnut_tudj` | — |
| S3-10 | zamjena imena dva fajla na disku | `id` ≠ ime ⇒ upozorenje; sadržaj ostaje vezan za svoj `id` | `s3_10_zamjena_imena` | — |
| S3-11 | `vault.json` dobije tuđi `recipients` (R7) | ignoriše se; novi fajl tuđ ključ ⛔ čita | `s3_11_vault_json_primaoci` | — |
| S3-12 | `vault.json` kaže `format: 2` | odbij otključavanje za pisanje | `s3_12_veci_format` | — |
| S3-13 | podmetnut `key.recovery.age` (procurio javni ključ za oporavak) | oporavak odbijen: paket ne ovjerava postojeće fajlove | `s3_13_podmetnut_recovery` | — |
| S3-14 | oblak ne vidi ništa otvoreno | nijedno ime, putanja ni rečenica u bajtovima foldera | `s3_14_nista_otvoreno` | pretraga oblaka + Spotlight (R15) |
| S3-15 | veličina ne otkriva dužinu imena | isti broj bajtova za kratko i dugo ime | `s3_15_dopuna` | — |
| S3-16 | stari model (28.10.) nad istim provjerama | 14 i 11 **crveno** nad starim, **zeleno** nad novim | `stari_model_*` | — |

---

## 7. Neprovjereno i provjereno

**Provjereno (izvor: paketi preuzeti sa crates.io kroz `cargo` 18.11.2026, fajl `Cargo.toml` u paketu):**
- `age 0.12.1`: `license = "MIT OR Apache-2.0"`, `rust-version = "1.74"` — https://crates.io/crates/age/0.12.1 (ranije mjereno i 0.11.5, ista licenca).
- `age 0.12.1` `CHANGELOG.md` u paketu: „## [0.11.5, 0.12.1] - 2026-07-14 … `age::armor::ArmoredReader`: It now correctly implements the intended strict parsing profile“ — https://crates.io/crates/age/0.12.1 . Promjene i uticaj na format: v. „Odluke v1“ (odluka 7).
- `bip39 3.0.0`: `license = "CC0-1.0"` — https://crates.io/crates/bip39/3.0.0
- `hmac 0.12.1`, `sha2 0.10.9`: `license = "MIT OR Apache-2.0"`; `bech32 0.11` (ista verzija koju koristi `age 0.12.1`, `[dependencies.bech32] version = "0.11"` u njegovom `Cargo.toml`).
- `age 0.11.5` `src/x25519.rs` (u 0.12.1 premješteno u `src/native/x25519.rs`): tajni ključ je bech32 `age-secret-key-` nad 32 bajta, `generate()` koristi `OsRng` — čitano u izvoru paketa.
- `age 0.12.1` `src/native/scrypt.rs`: podrazumijevani cilj ≈ 1 s (`ONE_SECOND`), čitač prihvata do cilj+4 (`max_work_factor = target_work_factor + 4`).

**`[IZMJERENO 18.11.2026]` na Linuxu x86_64 (rustc 1.97.0):** `cargo test` u `crate/` ⇒ `test result: ok. 27 passed; 0 failed` nad 0.11.5, a 19.11. nad 0.12.1 `28 passed`. `age` CLI 1.1.1 (`/usr/bin/age`, Debian paket) sa ključem iz 24 riječi (`cargo run --example bez_mdai`) ⇒ `age -d -i ključ.txt <id>.age` vraća 4096 bajtova čiji početak je `{"v":1,…,"path":"Notes/plan.md",…}` i tijelo `# Plan`. ⛔ Nije mjereno na Macu, Windowsu ni telefonu.

**`[NEPROVJERENO]`:** sve o ponašanju iCloud, Dropbox, OneDrive i Google klijenata (imena kopija, tihi gubitak, ignorisanje `tmp/`, izlaganje polovičnog fajla); vrijeme scrypt-a na telefonu; postoji li gotov pregledan format sa šifrovanim imenima (S8); da li je HMAC prihvatljiv recenzentu kao „standardan primitiv“.
