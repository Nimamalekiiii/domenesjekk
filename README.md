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