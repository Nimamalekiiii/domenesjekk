import socket
import ssl
import sys
from datetime import datetime, timezone

import dns.resolver
import requests

REKKEFOLGE = {"HØY": 0, "MIDDELS": 1, "LAV": 2, "INFO": 3, "OK": 4}


def lag_funn(tema, niva, funn, tiltak=""):
    return {"tema": tema, "niva": niva, "funn": funn, "tiltak": tiltak}


def hent_txt(navn):
    try:
        svar = dns.resolver.resolve(navn, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return [b"".join(r.strings).decode() for r in svar]


def sjekk_spf(domene):
    spf = [t for t in hent_txt(domene) if t.startswith("v=spf1")]
    if not spf:
        return lag_funn("SPF", "HØY", "Ingen SPF-oppføring funnet.",
                        "Legg til en SPF-oppføring i DNS med serverne som sender e-post for domenet.")
    if len(spf) > 1:
        return lag_funn("SPF", "HØY", "Domenet har flere SPF-oppføringer.",
                        "Slå dem sammen til én oppføring.")

    deler = spf[0].lower().split()

    if "+all" in deler or "all" in deler:
        return lag_funn("SPF", "HØY", "Alle servere får sende e-post for domenet (+all).",
                        "Bytt til -all eller ~all når alle ekte avsendere står i oppføringen.")
    if "-all" in deler:
        return lag_funn("SPF", "OK", "Ukjente servere skal avvises (-all).")
    if "~all" in deler:
        return lag_funn("SPF", "LAV", "Ukjente servere merkes som mistenkelige (~all).",
                        "Vurder -all når alle ekte avsendere er kartlagt.")
    if "?all" in deler:
        return lag_funn("SPF", "MIDDELS", "SPF tar ikke stilling til ukjente servere (?all).",
                        "Bytt til ~all eller -all.")
    if any(d.startswith("redirect=") for d in deler):
        return lag_funn("SPF", "INFO", "Reglene ligger i en annen SPF-oppføring (redirect).",
                        "Sjekk oppføringen det vises til.")
    return lag_funn("SPF", "MIDDELS", "SPF-oppføringen mangler en all-regel.",
                    "Avslutt oppføringen med ~all eller -all.")


def sjekk_dmarc(domene):
    navn = f"_dmarc.{domene}"
    dmarc = [t for t in hent_txt(navn) if t.startswith("v=DMARC1")]

    if not dmarc:
        return lag_funn("DMARC", "HØY", "Ingen DMARC-oppføring funnet.",
                        "Start med p=none og rapporter, og stram inn til quarantine eller reject.")

    for del_ in dmarc[0].split(";"):
        del_ = del_.strip()
        if del_.startswith("p="):
            policy = del_[2:].lower()
            if policy == "reject":
                return lag_funn("DMARC", "OK", "Forfalsket e-post skal avvises (p=reject).")
            if policy == "quarantine":
                return lag_funn("DMARC", "LAV", "Forfalsket e-post behandles som mistenkelig (p=quarantine).",
                                "Vurder p=reject når all ekte e-post består kontrollen.")
            if policy == "none":
                return lag_funn("DMARC", "MIDDELS", "Domenet overvåker bare, og forfalsket e-post stoppes ikke (p=none).",
                                "Gå over til quarantine når ekte e-post består kontrollen.")
            return lag_funn("DMARC", "MIDDELS", f"Ukjent DMARC-policy ({policy}).",
                            "Rett policyen til none, quarantine eller reject.")

    return lag_funn("DMARC", "MIDDELS", "DMARC-oppføringen mangler policy.",
                    "Legg til p=none, p=quarantine eller p=reject.")


def sjekk_dkim(domene):
    selectors = ["default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail", "dkim"]
    funnet = []

    for selector in selectors:
        oppforinger = hent_txt(f"{selector}._domainkey.{domene}")
        if any("p=" in oppforing for oppforing in oppforinger):
            funnet.append(selector)

    if funnet:
        return lag_funn("DKIM", "OK", f"Fant DKIM-nøkkel på: {', '.join(funnet)}.")
    return lag_funn("DKIM", "INFO", "Fant ingen nøkkel på vanlige navn, men DKIM kan likevel være satt opp.",
                    "Spør e-postleverandøren, eller sjekk DKIM-signaturen i en sendt e-post.")


def sjekk_tls(domene):
    kontekst = ssl.create_default_context()
    try:
        with socket.create_connection((domene, 443), timeout=5) as tilkobling:
            with kontekst.wrap_socket(tilkobling, server_hostname=domene) as tls:
                sertifikat = tls.getpeercert()
                versjon = tls.version()
    except ssl.SSLCertVerificationError:
        return lag_funn("TLS", "HØY", "Sertifikatet kunne ikke verifiseres.",
                        "Sjekk at sertifikatet er gyldig og dekker domenet.")
    except OSError:
        return lag_funn("TLS", "HØY", "Fikk ikke kontakt med HTTPS på port 443.",
                        "Sjekk at nettsiden har HTTPS.")

    utlop = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(sertifikat["notAfter"]), timezone.utc
    )
    dager = (utlop - datetime.now(timezone.utc)).days

    if dager < 14:
        return lag_funn("TLS", "MIDDELS", f"Sertifikatet utløper om {dager} dager ({versjon}).",
                        "Forny sertifikatet, og sjekk at fornyelsen er automatisk.")
    return lag_funn("TLS", "OK", f"Sertifikatet varer i {dager} dager til ({versjon}).")


def sjekk_headere(domene):
    viktige = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
    ]
    try:
        svar = requests.get(f"https://{domene}", timeout=10)
    except requests.RequestException:
        return lag_funn("Headere", "INFO", "Fikk ikke hentet nettsiden.",
                        "Sjekk at nettsiden svarer på HTTPS.")

    mangler = [h for h in viktige if h not in svar.headers]
    if not mangler:
        return lag_funn("Headere", "OK", "Alle de fire headerne er satt.")

    niva = "MIDDELS" if len(mangler) >= 3 else "LAV"
    return lag_funn("Headere", niva, f"Mangler {len(mangler)} av 4: {', '.join(mangler)}.",
                    "Legg til headerne hos webhotellet, og test at nettsiden fortsatt virker.")


def skriv_rapport(domene, funn):
    print(f"\nSikkerhetsrapport for {domene}")
    print("=" * 40)

    for f in sorted(funn, key=lambda f: REKKEFOLGE[f["niva"]]):
        print(f"[{f['niva']}] {f['tema']}: {f['funn']}")
        if f["tiltak"]:
            print(f"    Tiltak: {f['tiltak']}")

    print("=" * 40)
    for niva in REKKEFOLGE:
        antall = sum(1 for f in funn if f["niva"] == niva)
        print(f"{niva}: {antall}")
    print("\nRapporten gjelder bare disse kontrollene og er ikke en fullstendig sikkerhetsvurdering.")


if len(sys.argv) != 2:
    print("Bruk: python sjekk.py domene.no")
    sys.exit(1)

domene = sys.argv[1]
funn = [
    sjekk_spf(domene),
    sjekk_dmarc(domene),
    sjekk_dkim(domene),
    sjekk_tls(domene),
    sjekk_headere(domene),
]
skriv_rapport(domene, funn)