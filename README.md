# Domenesjekk

Mange småbedrifter har ingen sikkerhetsansvarlig og vet ikke om andre kan sende e-post i deres navn. Domenesjekk leser domenets offentlige DNS-oppføringer og forklarer SPF og DMARC på vanlig norsk.

Verktøyet angriper ingenting og vurderer bare det domenet selv har publisert. Resultatet er ikke en fullstendig sikkerhetsvurdering.

## Kom i gang

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python sjekk.py example.no
```



## Resultat på eget domene

Jeg kjørte Domenesjekk på porteføljesiden min og fant at alle de fire sikkerhetsheaderne manglet. Jeg la dem inn i `.htaccess`, testet siden i Safari og kjørte sjekken på nytt.

| Kontroll | Før | Etter |
|---|---|---|
| Sikkerhetsheadere | Mangler 4 av 4 | Alle 4 er satt |
| Funn på MIDDELS | 1 | 0 |
| Funn på OK | 2 | 3 |

CSP ble først testet i Report-Only, men Safari viste at den trengte `report-to` for å ha effekt. Derfor ble den testet direkte, med en enkel vei tilbake. `style-src` bruker `'unsafe-inline'` fordi siden har `style`-attributter.