"""Hungarian business-oriented phrase bank for security findings.

Mapped to scan check_ids in checkers/.
"""
from __future__ import annotations


HEADER_DESCRIPTIONS = {
    "Strict-Transport-Security (HSTS)": "A kapcsolat nem kényszeríti a biztonságos kommunikációt, ami lehetőséget ad a forgalom manipulálására vagy lehallgatására.",
    "Content-Security-Policy (CSP)": "Nincs védelem a rosszindulatú szkriptek ellen – egy esetleges támadás során a böngésző nem képes megkülönböztetni a legitim és a manipulált tartalmat.",
    "X-Frame-Options": "A webhely külső oldalakba ágyazható, ami megtévesztéses támadások (pl. felhasználói műveletek kicsalása) alapját képezheti.",
    "X-Content-Type-Options": "A böngésző nem kap egyértelmű utasítást a tartalomtípusok kezelésére, ami hibás vagy rosszindulatú végrehajtást eredményezhet.",
    "Referrer-Policy": "A webhely felesleges információkat adhat át külső szolgáltatóknak, ami adatvédelmi és üzleti szempontból is kockázatot jelent.",
    "Permissions-Policy": "Nincs korlátozás a böngésző érzékeny funkcióira, ami egy esetleges kompromittálás során növeli a visszaélés lehetőségét.",
}


CHECK_ID_TO_HEADER = {
    "headers.hsts.missing": "Strict-Transport-Security (HSTS)",
    "headers.hsts.weak": "Strict-Transport-Security (HSTS)",
    "headers.hsts.no_subdomains": "Strict-Transport-Security (HSTS)",
    "headers.csp.missing": "Content-Security-Policy (CSP)",
    "headers.csp.weak": "Content-Security-Policy (CSP)",
    "headers.xfo.missing": "X-Frame-Options",
    "headers.xfo.invalid": "X-Frame-Options",
    "headers.xfo.frame_ancestors_permissive": "X-Frame-Options",
    "headers.xcto.missing": "X-Content-Type-Options",
    "headers.referrer.missing": "Referrer-Policy",
    "headers.referrer.weak": "Referrer-Policy",
    "headers.permissions.missing": "Permissions-Policy",
}


HEADERS_SECTION_CLOSER = (
    "A fenti hiányosságok együtt egy olyan alapbiztonsági szintet eredményeznek, "
    "amely nem felel meg a mai üzleti elvárásoknak."
)


COOKIE_SECTION = {
    "title": "Session cookie biztonsági hiányosságok",
    "lead": (
        "A scan a webhely által küldött munkamenet-süti elemzése során az alábbi "
        "hiányosságokat azonosította:"
    ),
    "bullets": {
        "secure": (
            "Hiányzó Secure flag – A munkamenet nem kizárólag titkosított kapcsolaton "
            "keresztül kerül továbbításra, így bizonyos környezetekben lehallgathatóvá válhat."
        ),
        "httponly": (
            "Hiányzó HttpOnly flag – A süti elérhető a böngészőben futó szkriptek számára, "
            "ami egy esetleges sérülékenység esetén lehetővé teheti a munkamenet eltulajdonítását."
        ),
        "samesite": (
            "Hiányzó SameSite flag – A munkamenet külső kérésekben is felhasználható, "
            "ami növeli a visszaélések lehetőségét."
        ),
    },
    "closer": (
        "Gyakorlati szinten ez azt jelenti, hogy egy támadó megfelelő körülmények között "
        "átveheti egy felhasználó aktív munkamenetét, és jogosulatlanul hozzáférhet az "
        "oldalon kezelt adatokhoz."
    ),
}


TLS_SECTION = {
    "title": "TLS / SSL konfigurációs hiányosságok",
    "lead": (
        "A titkosított kommunikáció vizsgálata során az alábbi konfigurációs "
        "hiányosságok azonosíthatók:"
    ),
    "bullets": {
        "ssl.no_tls": (
            "A webhely nem HTTPS-en keresztül érhető el – a teljes kommunikáció "
            "titkosítatlan, jelszavak, sütik és személyes adatok lehallgathatók."
        ),
        "ssl.cert.expired": (
            "Lejárt tanúsítvány – a böngészők figyelmeztetést jelenítenek meg, "
            "ami közvetlen bizalomvesztést és látogatószám-csökkenést okoz."
        ),
        "ssl.cert.expiring": (
            "Hamarosan lejáró tanúsítvány – soron kívüli megújítás szükséges, "
            "a megújítás elmaradása szolgáltatás-kiesést okozhat."
        ),
        "ssl.cert.expiring_soon": (
            "30 napon belül lejáró tanúsítvány – javasolt a megújítási folyamat "
            "ütemezett indítása."
        ),
        "ssl.cert.weak_key": (
            "Gyenge kriptográfiai kulcsméret – nem felel meg a jelenlegi iparági "
            "ajánlásoknak, megfelelőségi audit során hiányosságként kerülhet rögzítésre."
        ),
        "ssl.cert.untrusted": (
            "Nem hitelesített tanúsítványlánc – a böngészők nem fogadják el "
            "automatikusan, ami felhasználói oldalon biztonsági figyelmeztetést okoz."
        ),
        "ssl.cert.hostname_mismatch": (
            "Hostnév-eltérés – a tanúsítvány nem a vizsgált domainre lett kiállítva, "
            "ami szakszerűtlen üzemeltetésre utal."
        ),
        "ssl.protocol.ssl_2_0_cipher_suites": (
            "Elavult SSLv2 protokoll támogatott – kritikus szintű kriptográfiai hiba, "
            "amely 20+ éves támadásokkal kihasználható."
        ),
        "ssl.protocol.ssl_3_0_cipher_suites": (
            "Elavult SSLv3 protokoll támogatott (POODLE támadás) – azonnali letiltása "
            "szükséges, megfelelőségi szempontból blokkoló tényező."
        ),
        "ssl.protocol.tls_1_0_cipher_suites": (
            "Elavult TLS 1.0 protokoll támogatott – a PCI-DSS megfelelőség kifejezetten "
            "tiltja, sok modern böngésző már nem fogadja el."
        ),
        "ssl.protocol.tls_1_1_cipher_suites": (
            "Elavult TLS 1.1 protokoll támogatott – iparági ajánlások alapján letiltandó."
        ),
        "ssl.protocol.no_modern": (
            "Nincs modern TLS protokoll támogatva – a webhely nem érhető el biztonságosan "
            "a jelenlegi böngészőkkel."
        ),
        "ssl.cipher.weak": (
            "Gyenge titkosítási algoritmusok engedélyezve – kriptográfiai szakmai "
            "minimum alatti konfiguráció."
        ),
    },
    "closer": (
        "Egy biztonságos titkosítási réteg a webhely alapszintű elvárása. Ezek a "
        "hiányosságok automatizált megfelelőségi szkennerek (pl. SSL Labs, ETSI) "
        "során egyértelműen kimutathatók."
    ),
}


SOURCE_SECTION = {
    "title": "Forráskódból azonosított problémák",
    "lead": "A webhely nyilvánosan elérhető forrásának elemzése során az alábbi megfigyelések tárhatók fel:",
    "bullets": {
        "source.mixed_content": (
            "Mixed content (titkosítatlan erőforrások HTTPS oldalon) – a böngésző "
            "blokkolhatja a tartalmat, és MITM-támadás során külső kód injektálható."
        ),
        "source.sri.missing": (
            "Külső scriptek integritás-ellenőrzés (SRI) nélkül – ha egy harmadik fél "
            "CDN-je kompromittálódik, az oldalon tetszőleges kód futhat, ami "
            "supply-chain jellegű kockázatot jelent."
        ),
        "source.form.http_action": (
            "Űrlap titkosítatlan célcímmel – a felhasználói adatok HTTP-n keresztül "
            "továbbítódnak, lehallgathatóak a hálózaton."
        ),
        "source.form.password_on_http": (
            "Jelszó mező titkosítatlan oldalon – kritikus adatvédelmi probléma, "
            "a jelszó tisztán megy át a hálózaton."
        ),
        "source.form.autocomplete_off": (
            "Jelszókezelőket akadályozó konfiguráció – gyengébb jelszóhasználathoz vezethet."
        ),
        "source.inline_handlers": (
            "Inline JavaScript eseménykezelők – akadályozzák a szigorú Content-Security-Policy "
            "bevezetését, és növelik az XSS-támadások hatókörét."
        ),
        "source.inline_scripts": (
            "Inline script blokkok – ugyanezen okból nehezítik a modern szkriptbiztonsági "
            "védelem bevezetését."
        ),
        "source.comments.leak": (
            "Gyanús kommentek a forráskódban – fejlesztői megjegyzések (TODO, jelszó-utalás, "
            "belső dokumentáció) szivároghatnak ki, ami támadói felderítéshez használható."
        ),
        "source.secret.exposed": (
            "Titoknak tűnő minta a HTML-ben – API kulcs / privát kulcs / token regex-illesztés "
            "alapján. Ha valódi titok, azonnal rotálandó."
        ),
        "source.lib.outdated": (
            "Régi vagy sebezhető JavaScript könyvtár – ismert biztonsági hibákkal rendelkező "
            "verziók futnak, amelyekre publikus exploit-ok léteznek."
        ),
        "source.csrf.hint": (
            "Nincs egyértelmű CSRF védelem a POST űrlapokon – kézi ellenőrzés javasolt."
        ),
    },
    "closer": (
        "A fenti megfigyelések összességében arra utalnak, hogy a webhely nincs rendszeres, "
        "kontrollált szakértői karbantartás alatt, ami nem felel meg a mai iparági elvárásoknak."
    ),
}


DISCLOSURE_SECTION = {
    "title": "Rendszer- és komponensinformációk felfedése",
    "lead": (
        "A szerver válaszfejlécei közvetlenül felfedik a kiszolgáló típusát és/vagy "
        "verzióját, ami a támadói felderítési fázist nagymértékben lerövidíti:"
    ),
    "closer": (
        "Egy automatizált tömeges szkenner ezen információk alapján pontosan célzott "
        "exploit-csomagot tud futtatni a webhelyen, anélkül hogy bármilyen aktív "
        "felderítést végezne."
    ),
}


CORS_SECTION = {
    "title": "Kritikus CORS misconfiguration (kiemelt kockázat)",
    "body": [
        "A fejlécvizsgálat során olyan konfiguráció azonosítható, amely külső domainek "
        "számára is engedélyezheti hitelesített kérések kezelését. Ez bizonyos környezetekben "
        "cross-origin adatkezelési és hozzáférési kockázatot jelenthet.",
        "Gyakorlati szinten ez azt jelenti, hogy egy külső weboldal megfelelő körülmények között "
        "képes lehet a felhasználó böngészőjén keresztül kéréseket kezdeményezni a rendszer felé, "
        "ami adatvédelmi és jogosultságkezelési problémákat vet fel.",
    ],
}


EXECUTIVE_SUMMARY_TEMPLATE = {
    "intro": "A {host} webhely a független biztonsági szkennelés során „{grade}\" minősítést kapott.",
    "intro_findings_summary": {
        "all_headers_missing": "A vizsgált hat biztonsági HTTP-fejléc közül egyik sincs konfigurálva, és a kiszolgálási réteg védelmi mechanizmusai nincsenek aktiválva.",
        "headers_partial": "A vizsgált biztonsági HTTP-fejlécek közül több is hiányzik vagy nem megfelelően konfigurált.",
        "tls_critical": "A titkosított kommunikáció rétege olyan hiányosságokat tartalmaz, amelyek a forgalom integritását és bizalmasságát veszélyeztetik.",
        "source_issues": "A forráskód-elemzés további, üzletileg releváns kockázatokat tárt fel.",
        "headers_ok": "A vizsgált biztonsági HTTP-fejlécek többsége konfigurálva van, ugyanakkor néhány terület további finomítást igényel.",
    },
    "risk_framing": (
        "A feltárt hiányosságok automatizált biztonsági szkennerek számára nyilvánosan "
        "azonosíthatók, ezért egy strukturált sérülékenység-felmérés keretében prioritizált "
        "kezelést igényelnek."
    ),
    "industry_template": (
        "Egy {industry} esetében ez közvetlen üzleti, jogi és reputációs kockázat. "
        "A {compliance} elvárások tükrében a jelenlegi konfiguráció dokumentálható hiányosságokat "
        "tartalmaz, amelyek partneri átvilágítás, pályázati eljárás vagy külső audit során "
        "negatív megítélést eredményezhetnek."
    ),
}


RISK_CLASSIFICATION = {
    "low": (
        "A {host} webhely jelenlegi állapota összességében elfogadható biztonsági szintet "
        "képvisel. A javítható területek a finomhangolás szintjén mozognak, és nem jelentenek "
        "azonnali kockázatot."
    ),
    "medium": (
        "A {host} webhely jelenlegi állapota részben megfelelő, ugyanakkor több, "
        "egymást erősítő hiányosság van egyidejűleg jelen. Ezek külső audit során "
        "dokumentálható hiányosságként kerülhetnek rögzítésre."
    ),
    "high": (
        "A {host} jelenlegi állapota nem pusztán „nem optimális\", hanem konkrétan azonosítható "
        "és kihasználható biztonsági hiányosságokat tartalmaz. Ezek a hiányosságok együttesen "
        "valós támadási felületet jelentenek – nem csupán elméleti, hanem jelenlegi működési "
        "kitettséget. Üzleti oldalról ez a kombináció különösen problémás: egy partner vagy "
        "beszállítói audit során az ilyen szintű hiányosságok bizalomvesztést okozhatnak, "
        "és akár együttműködés meghiúsulásához is vezethetnek."
    ),
}


OFFER_1 = {
    "title": "AJÁNLAT 1 – Részletes biztonsági és technikai audit",
    "subtitle": "Célzott, részletes vizsgálat a teljes támadási felület és kockázati térkép feltárására",
    "intro": (
        "A jelenlegi gyors-elemzés alapján több kritikus és üzletileg is releváns kockázat "
        "azonosítható, azonban ezek pontos kiterjedése és összefüggései csak egy célzott, "
        "részletes vizsgálattal határozhatók meg."
    ),
    "bullets": [
        "feltárja a teljes támadási felületet",
        "azonosítja a ténylegesen kihasználható sérülékenységeket",
        "üzleti szempontból is értelmezhető kockázati képet ad",
        "egyértelmű alapot biztosít a további döntésekhez",
    ],
    "result": (
        "Egy vezetői és technikai jelentés, amely alapján eldönthető, hogy a jelenlegi rendszer "
        "javítása vagy teljes megújítása indokolt."
    ),
    "duration_default": "2–4 munkanap",
    "price_default": "100 000 – 180 000 Ft + ÁFA",
    "footer": (
        "Az audit nem teljes körű penetrációs teszt, hanem célzott biztonsági és technikai "
        "felmérés a feltárt kockázatok pontosítására. Az audit célja nem pusztán a hibák "
        "feltárása, hanem egy egyértelmű döntési helyzet megteremtése a legkisebb kockázatú "
        "és legköltséghatékonyabb irány kiválasztásához."
    ),
}


OFFER_2 = {
    "title": "AJÁNLAT 2 – Teljes webhely-újraépítés (Secure by Design)",
    "subtitle": "Hosszú távú, fenntartható megoldás új technológiai alapokon",
    "bullets": [
        "korszerű, jövőálló technológiai alapok",
        "beépített biztonsági szemlélet a teljes működésben",
        "egységes és megfelelőségi szempontból is átgondolt adatkezelés",
        "gyors, stabil és üzletileg is megbízható működés",
        "több évre előre biztosított karbantarthatóság",
    ],
    "why": (
        "A jelenlegi rendszer több rétegben módosított, elavult alapokra épül, ami hosszabb "
        "távon folyamatos kockázatot és növekvő fenntartási költséget jelenthet."
    ),
    "duration_default": "4–8 hét",
    "price_default": "A végleges költség a jelenlegi rendszer állapotától és a szükséges beavatkozás mértékétől függ",
}


NEXT_STEP_TEMPLATE = (
    "A {host} jelenlegi állapotában több, egymást erősítő biztonsági hiányosság van egyidejűleg "
    "jelen, amelyek együtt már nem tekinthetők elfogadható kockázati szintnek. Ezek a "
    "hiányosságok dokumentálhatók és egy külső audit során egyértelműen kimutathatók – "
    "ami azt jelenti, hogy üzleti és megfelelőségi szempontból sem hagyhatók figyelmen kívül.\n\n"
    "Javaslatunk: első lépésként egy részletes audit elvégzése, amely pontos képet ad a "
    "kockázatok valódi mértékéről, és objektív alapot biztosít a szükséges beavatkozások "
    "prioritizálásához."
)


def grade_to_risk_level(grade: str) -> str:
    if grade in ("A", "B"):
        return "low"
    if grade == "C":
        return "medium"
    return "high"
