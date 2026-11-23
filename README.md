# mdai-vault — referentna implementacija formata šifrovanog trezora v1

Spec: `SPEC-FORMAT-TREZORA-V1.md` (u korijenu repoa). Samo jezgro formata: bez UI-ja, Tauri-ja, mreže i telemetrije; `#![forbid(unsafe_code)]`.
Zavisnosti: `age =0.12.1` (X25519 + scrypt), `hmac` + `sha2` (HMAC-SHA256, spec R8), `bip39` (samo kodiranje 32 bajta ⇄ 24 riječi, spec R19), `bech32 0.11` (ista verzija kao u `age`-u), `rand` (OS RNG), `serde`/`serde_json`, `zeroize`.

## Licenca

Copyright 2026 Goran Jovanović. Apache-2.0 (vidi `LICENSE` i `NOTICE`). Zavisnost `age 0.12.1` ostaje pod svojom licencom (`MIT OR Apache-2.0`).

⚠️ Lozinka i 24 riječi su jedini način da se trezor otvori; ako se oboje izgubi, trezor je izgubljen i nema oporavka.

## Pokretanje

```
cargo test
```
Očekivano: `tests/format.rs`: `test result: ok. 29 passed; 0 failed`; `tests/negativni.rs`: `test result: ok. 8 passed; 0 failed` (macOS, rustc 1.97.1, age 0.12.1, 23.11.2026).

Ručna provjera „bez mdai-ja“ (traži `age` CLI):
```
cargo run --example bez_mdai -- /tmp/probni-trezor     # ispiše RIJECI=, KLJUC=, FAJL=
echo "<KLJUC>" > /tmp/k.txt && age -d -i /tmp/k.txt <FAJL> | head -c 1024
```

## Testovi ⇄ tabela S3 (spec §6)
`s3_1` … `s3_15` po redu tabele; `format_isti_poslije_age_0_12_1` = fajl napisan nad age 0.11.5 (`tests/fixtures/`) se otvara nad 0.12.1; `tok_*` = tokovi §5; `r19_*` i `bez_mdai_ja_*` = 24 riječi; `stari_model_*` = isti scenario nad modelom od 28.10. (stariji model), namjerno **crveno** (test potvrđuje da stari model curi), dok odgovarajući `s3_11` i `s3_14` pokazuju **zeleno** za v1.

## Šta testovi ⛔ ne dokazuju
- Ponašanje iCloud, Dropbox, OneDrive, Google klijenata: oblak je simuliran kopiranjem bajtova (`offline_write`). Da li klijent pravi kopiju, tiho gubi verziju ili izlaže pola fajla mjeri sonda S3.
- Bezbjednost same kriptografije (`age`, HMAC): koristi se, ne provjerava.
- Brisanje tajni iz memorije: `zeroize` je primijenjen, ali test to ne mjeri; swap/hibernacija i JS strana van obima (Q12).
- Jačinu lozinke i trajanje scrypt-a: testovi koriste `log_n = 10` (`insecure_fast_for_tests`); pravi minimum je 18 (`CreateOptions::standard`), cijena na telefonu = S4.
- Rad na Macu, Windowsu, iOS-u, Androidu (mjereno na Linuxu i macOS-u; Windows, iOS i Android nisu pokrenuti); atomičnost `rename` na mrežnim/sinhronizovanim volumenima.
- Istovremeni upis dva procesa na istom računaru; više od 16 predaka u lancu (`anc`) kod dugih offline grana — tada se dobije kopija sukoba više, ne gubitak.
- Rollback za uređaj koji trezor vidi prvi put (nema lokalnog stanja).
- Performanse (S6: 1000 bilješki).
