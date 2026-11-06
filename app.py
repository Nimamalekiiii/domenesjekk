import re

import dns.exception
from flask import Flask, render_template, request

from sjekk import REKKEFOLGE, kjor_alle_sjekker

app = Flask(__name__)

GYLDIG_DOMENE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def rens_domene(tekst):
    domene = tekst.strip().lower()
    domene = domene.removeprefix("https://").removeprefix("http://")
    domene = domene.removeprefix("www.").split("/")[0]
    if GYLDIG_DOMENE.fullmatch(domene):
        return domene
    return None


@app.route("/", methods=["GET", "POST"])
def forside():
    domene = None
    funn = None
    feil = None

    if request.method == "POST":
        domene = rens_domene(request.form.get("domene", ""))
        if domene is None:
            feil = "Skriv inn et gyldig domene, for eksempel bedrift.no."
        else:
            try:
                funn = sorted(kjor_alle_sjekker(domene), key=lambda f: REKKEFOLGE[f["niva"]])
            except dns.exception.DNSException:
                feil = "Fikk ikke svar fra DNS. Prøv igjen om litt."

    return render_template("index.html", domene=domene, funn=funn, feil=feil)


if __name__ == "__main__":
    app.run(port=5001)