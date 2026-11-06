import sys
import dns.resolver
import requests

import socket
import ssl
from datetime import datetime, timezone

def hent_txt(navn):
    try:
        svar = dns.resolver.resolve(navn, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return [b"".join(r.strings).decode() for r in svar]

def sjekk_spf(domene):
    spf = [t for t in hent_txt(domene) if t.startswith("v=spf1")]
    if not spf:
        return "MANGLER: ingen SPF-oppføring"
    if len(spf) > 1:
        return "FEIL: flere SPF-oppføringer"

    deler = spf[0].lower().split()

    if "+all" in deler or "all" in deler:
        return "FARLIG: alle servere får sende e-post for domenet (+all)"
    if "-all" in deler:
        return "STERK: ukjente servere skal avvises (-all)"
    if "~all" in deler:
        return "MIDDELS: ukjente servere merkes som mistenkelige (~all)"
    if "?all" in deler:
        return "SVAK: SPF tar ikke stilling til ukjente servere (?all)"
    if any(d.startswith("redirect=") for d in deler):
        return "UKJENT: reglene ligger i en annen SPF-oppføring (redirect)"

    return "SVAK: SPF-oppføringen mangler en all-regel"

def sjekk_dmarc(domene):
    navn = f"_dmarc.{domene}"
    dmarc = [t for t in hent_txt(navn) if t.startswith("v=DMARC1")]

    if not dmarc:
        return "MANGLER: ingen DMARC-oppføring"

    for del_ in dmarc[0].split(";"):
        del_ = del_.strip()
        if del_.startswith("p="):
            policy = del_[2:]
            if policy == "reject":
                return "STERK: forfalsket e-post skal avvises (p=reject)"
            if policy == "quarantine":
                return "GOD: forfalsket e-post skal behandles som mistenkelig (p=quarantine)"
            if policy == "none":
                return "SVAK: domenet overvåker bare, forfalsket e-post stoppes ikke (p=none)"
            return f"FEIL: ukjent policy ({policy})"

    return "FEIL: fant ingen policy"


def sjekk_tls(domene):
    kontekst = ssl.create_default_context()
    try:
        with socket.create_connection((domene, 443), timeout=5) as tilkobling:
            with kontekst.wrap_socket(tilkobling, server_hostname=domene) as tls:
                sertifikat = tls.getpeercert()
                versjon = tls.version()
    except ssl.SSLCertVerificationError:
        return "FEIL: sertifikatet kunne ikke verifiseres"
    except OSError:
        return "MANGLER: fikk ikke kontakt med HTTPS på port 443"

    utlop = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(sertifikat["notAfter"]), timezone.utc
    )
    dager = (utlop - datetime.now(timezone.utc)).days

    if dager < 14:
        return f"VARSEL: sertifikatet utløper om {dager} dager ({versjon})"
    return f"OK: sertifikatet varer i {dager} dager til ({versjon})"

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
        return "FEIL: fikk ikke hentet nettsiden"

    mangler = [h for h in viktige if h not in svar.headers]
    if not mangler:
        return "OK: alle de fire headerne er satt"
    return f"MANGLER {len(mangler)} av 4: {', '.join(mangler)}"

domene = sys.argv[1]
print("SPF:", sjekk_spf(domene))
print("DMARC:", sjekk_dmarc(domene))
print("TLS:", sjekk_tls(domene))
print("Headere:", sjekk_headere(domene))
