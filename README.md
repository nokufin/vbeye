# vbeye

**Passive Web Security Assessment Tool** · v1.0.0 · Developed by theEreb0x

Nyilvános web target gyors kibervédelmi auditja **3 modullal**:

- **headers** – Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookie flag-ek, információ-szivárgás (Server / X-Powered-By)
- **ssl** – TLS verziók (SSLv2/v3, TLS 1.0–1.3 elfogadottság), cipher suite-ek (gyenge: RC4, 3DES, NULL, EXPORT, anon), tanúsítvány-lánc, lejárat, hostnév-egyezés, kulcsméret
- **source** – Mixed content, külső script SRI nélkül, űrlapok HTTP action-nel / password mezővel, inline event handlerek, gyanús HTML kommentek, kiszivárgott titok-minták (AWS/Google/Slack key, JWT, private key), elavult JS library-k, CSRF token hint

A futás végén:
- színes CLI összefoglaló (score 0–100, A–F érdemjegy, súlyozott),
- önálló HTML jelentés (offline böngészhető, megosztható az ügyféllel),
- opcionálisan JSON kimenet (CI/CD-be),
- opcionálisan üzleti-stílusú DOCX deliverable (ügyfél-átadható, branding-elve).

**Minden finding `confidence` szintet kap:** `VERIFIED` (közvetlen megfigyelés), `STRONG INDICATOR` (erős jel), `REQUIRES_MANUAL_VALIDATION` (heurisztika, kézi vizsgálat). A riportok színes badge / inline marker formájában jelölik, így minden megállapítás külön-külön védhető egy ügyfélkérdezés során.

## Telepítés

### Kali (pipx javasolt)

```bash
sudo apt install -y pipx
pipx install .
```

Ezután `vbeye` elérhető a PATH-on.

### Fejlesztői módban (venv)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Használat

```bash
vbeye example.com
vbeye https://example.com
vbeye example.com --skip ssl                # csak headers + source
vbeye example.com -o report.html            # explicit kimenet
vbeye example.com --json result.json        # gépi feldolgozáshoz
vbeye example.com --no-html                 # csak terminál
vbeye example.com --timeout 30              # lassú szerverekhez
```

Default: HTML report a `./reports/<host>_<timestamp>.html` útra.

## DOCX deliverable (ügyfél-átadható jelentés)

A scan eredményéből generálhatsz egy üzleti-stílusú Word dokumentumot:

```bash
# Automatikus útvonal (./reports/<host>_<ts>.docx)
vbeye example.com --docx

# Egyedi útvonal
vbeye example.com --docx /tmp/audit_report.docx

# Iparág + megfelelőségi keret a vezetői összefoglalóhoz
vbeye example.com --docx \
  --industry "ipari kivitelező vállalat" \
  --compliance "NIS2 és GDPR" \
  --price "150 000 – 220 000 Ft + ÁFA"

# Szektor-specifikus vezetői szöveg: az --industry értékét kulcsszó alapján
# klasszifikáljuk és sektor-specifikus business-context paragrafust választunk:
#   "hotel", "szálloda", "panzió"             → vendéglátás / foglalási bizalom
#   "gyártó", "ipari", "automotive"           → beszállítói audit / ISO 27001
#   "önkormányzat", "hivatal", "minisztérium" → lakossági bizalom / NIS2
#   "WordPress KKV", "kkv"                    → SEO spam / SMTP abuse

# Ajánlat 1 ár elrejtése
vbeye example.com --docx --price ""
```

### Konfiguráció

A céges adatok (név, email, weboldal, színek) és az alapértelmezett árazás `vbeye.toml`-ba kerül. Példa:

```bash
cp vbeye.toml.example vbeye.toml
# szerkeszd a saját adataidra
```

Keresési sorrend:
1. `./vbeye.toml` (projekt-szintű)
2. `$VBEYE_CONFIG` env változó útvonala
3. `~/.config/vbeye/config.toml`
4. `~/.vbeye.toml`

Vagy explicit: `vbeye ... --config /path/to/config.toml`.

### A DOCX szerkezete

A jelentés a következő szakaszokat tartalmazza:

1. **Vezetői összefoglaló** — dinamikus, a tényleges találatok és az `--industry`/`--compliance` alapján
2. **Technikai megállapítások**
   - 2.1 Hiányzó / nem megfelelő biztonsági HTTP-fejlécek
   - 2.X adaptív alszekciók (csak akkor jelennek meg, ha a scan találatot talált):
     - Session cookie biztonsági hiányosságok
     - TLS / SSL konfigurációs hiányosságok
     - Rendszer- és komponensinformációk felfedése
     - Forráskódból azonosított problémák
3. **Kockázati besorolás** — ALACSONY / KÖZEPES / MAGAS, grade alapján
4. **Javasolt megoldások** — Ajánlat 1 (részletes audit) + Ajánlat 2 (újraépítés)
5. **Javaslat és következő lépés**

A logót, fejlécet és a céges layout-ot manuálisan kell beilleszteni a generált docx-be (egyszer). Tipp: nyisd meg a generált docx-et és a saját céges sablonodat párhuzamosan, majd másold be a fejlécet/láblécet.

### Exit kódok

| Kód | Jelentés |
|-----|----------|
| 0   | Nincs HIGH/CRITICAL finding |
| 2   | Van legalább egy HIGH vagy CRITICAL |

CI-ban használva így bukik el a pipeline súlyos hiba esetén:

```yaml
- run: vbeye ${{ inputs.target }} --json out.json
```

## Scoring

100-ból indul, minden finding levon a súlyozása szerint:

| Severity | Levonás |
|----------|---------|
| CRITICAL | 35 |
| HIGH | 18 |
| MEDIUM | 8 |
| LOW | 3 |
| INFO / OK | 0 |
| Checker hiba | 5 |

**Kategória-cap**: minden modul max ennyit vonhat le (hogy egy kategória ne ölje meg a score-t):
- headers: 30
- source: 35
- ssl: 50

**E-floor**: ha nincs valódi kritikus problémás (HTTP-only, lejárt cert, mixed content, plaintext password form, leaked secret) ÉS nincs 3+ HIGH finding sem, a score nem eshet 30 alá (E max). Ez védi a modern HTTPS oldalakat a "minden hardening hiányos → automatikus F" reflextől.

| Score | Grade |
|-------|-------|
| 90+ | A |
| 80–89 | B |
| 65–79 | C |
| 50–64 | D |
| 30–49 | E |
| <30 | F (csak valós kritikus mellett) |

## Validation szintek

Minden finding kap egy `confidence` mezőt — a riportokban (HTML badge + DOCX inline marker) látható:

| Szint | Mit jelent | Példa |
|---|---|---|
| **VERIFIED** | Közvetlen, megerősített megfigyelés a szerverválaszból | Hiányzó HSTS header, lejárt cert, HTTP form action |
| **STRONG INDICATOR** | Erős jel, kiegészítő megerősítéssel pontosítható | CSP wildcard heurisztika, SRI external script, lib URL pattern |
| **REQUIRES_MANUAL_VALIDATION** | Heurisztika, kézi validáció szükséges | Gyanús HTML komment, generic key=value secret minta, CSRF token hint |

Egy ügyfél vagy reviewer nem tudja false-positive-ként visszadobni a riportot, mert a tool maga jelöli a heurisztikus megállapításokat.

## Biztonságos használat

A vbeye **passzív** auditot végez:

- Egyetlen `HTTP GET` a célpontra (mint a böngésződ)
- TLS handshake-ek a támogatott protokollok és cipher suite-ek listázásához (mint egy normál kliens kapcsolódáskor)
- A szerver által visszaadott HTML/JS tartalom statikus elemzése (mint egy webcrawler)

**Nincs benne** aktív sebezhetőség-exploitálás, payload-injektálás, brute-force, könyvtár-enum, sem semmilyen olyan funkció, amely a célpontot a normál kliens-szerű forgalmon túl terhelné. Ennek ellenére javasolt csak olyan célpontot vizsgálni, ahol erre szakmai indokod van (saját infra, pentest scope, bug bounty engedély, ügyfél-megbízás).

## Architektúra

```
vbeye/
├── cli.py              # argparse + orchestration
├── scoring.py          # Finding, Severity, score
├── report.py           # HTML report
└── checkers/
    ├── headers.py
    ├── ssl.py          # sslyze wrapper
    └── source.py
```

Új modul hozzáadásához:
1. Hozz létre `vbeye/checkers/myname.py` fájlt egy `run(url, timeout) -> CheckerResult` függvénnyel.
2. Regisztráld a `cli.py` `modules` listájában.

## Roadmap (ötletek)

- DNS / SPF / DMARC / DKIM modul
- robots.txt / sitemap szivárgás-ellenőrzés
- Subdomain enum (passzív, crt.sh)
- WAF detection
- Párhuzamos scan több targetre
- Plugin entry point (pyproject `entry_points`)
- Webhook integráció (Slack/Teams a HTML report linkkel)
