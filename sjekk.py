import sys
import dns.resolver

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

domene = sys.argv[1]
print("SPF:", sjekk_spf(domene))
print("DMARC:", sjekk_dmarc(domene))