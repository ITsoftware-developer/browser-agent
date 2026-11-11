# Browser Agent

Lokaal dashboard voor website-QA. De demo gebruikt Playwright met Microsoft Edge en heeft geen API-sleutel nodig.

## Starten

Voer dit vanuit de projectmap uit met Node.js 22 of hoger en Microsoft Edge geïnstalleerd.

```powershell
npm ci
npm start
```

Open [het dashboard](http://127.0.0.1:4317). Kies **Demo met fout**, vink de toestemming aan en klik op **Start demotest**. De vijf scenario’s zijn zoeken, categorieën filteren, productdetails openen, toevoegen aan de winkelwagen en de betaalstap bereiken. De muis activeert in de foutdemo een bug. Het toetsenbord kan wel in de winkelwagen, zodat de betaalstap apart kan worden getest. **Werkende demo** gebruikt dezelfde browsercontroles en de variant met een werkende winkelwagen.

Rapporten en screenshots staan per test in `runs/<id>/`. De browser die de test start krijgt toegang via zijn sessiecookie. Het JSON-rapport verwijst naar de bijbehorende screenshots. Querystrings, fragmenten en eventuele inloggegevens in webadressen worden uit de gerapporteerde URL’s verwijderd. De oorspronkelijke URL wordt gebruikt voor de paginalaadactie. Rapporten van vóór deze sessiekoppeling zijn via de bestanden in `runs/` terug te vinden.

## Publieke website controleren

Plak een publieke HTTP(S)-URL waarvoor je toestemming hebt en klik op **Start websitetest**. Browser Agent controleert de HTTP-respons, paginatitel en zichtbare inhoud. Met **Te controleren tekst** voeg je een controle op zichtbare of afwezige tekst toe. Deze modus heeft geen API-sleutel of testopdracht nodig. De preview toont opnamen van de pagina zoals die voor een nieuwe bezoeker wordt geladen.

### Passieve beveiligingscontrole

Vink **Passieve beveiligingscontrole** aan om de uiteindelijke documentrespons ook te beoordelen op HTTPS, HSTS, CSP, `nosniff`, cookie-attributen en software-informatie in responseheaders. De controle gebruikt de bestaande paginalaadactie. Onder **Beveiligingscontrole** en in het JSON-rapport staat per waarneming het bewijs, eventueel hersteladvies en de toepasselijke verwijzing naar [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/releases/tag/v5.0.0).

Een melding **Te beoordelen** beschrijft een configuratiesignaal in de bemonsterde respons. Cookie-attributen worden geanalyseerd zonder cookie-namen of -waarden op te slaan. Een volledige TLS-configuratiecontrole, een dependency-audit en actieve tests vragen aparte gegevens en testopzet.

### Strikte modus met DNS-verificatie

Zet `REQUIRE_DOMAIN_VERIFICATION=1` vóór het starten van de server om externe runs te beperken tot door jouw browsersessie geverifieerde origins. Vul een publieke website-URL in, open **Domeinverificatie**, genereer een TXT-record en voeg de getoonde naam en waarde toe bij je DNS-provider. Klik vervolgens op **Verifieer domein**. Het bewijs geldt voor het exacte schema, de hostnaam en de poort. Bijvoorbeeld `https://voorbeeld.nl` en `https://www.voorbeeld.nl` hebben aparte verificaties.

Een TXT-code blijft vijftien minuten geldig. Een succesvolle verificatie blijft 24 uur geldig zolang deze server draait. Na een serverherstart kun je een nieuw record genereren. In strikte modus worden doorverwijzingen en netwerkverzoeken buiten de geverifieerde origins beperkt.

## AI-modus voor een eigen testsite

Stel voor een testomgeving met fictieve gegevens de volgende variabelen in voordat je de server start.

```powershell
$env:TEST_ORIGINS = 'https://staging.jouw-domein.nl'
$env:LLM_ENDPOINT = 'https://jouw-modelprovider.example/v1/chat/completions'
$env:LLM_MODEL = 'jouw-modelnaam'
# Stel LLM_API_KEY in via je eigen omgevingsconfiguratie als de provider die vereist.
npm start
```

De planner verwacht een Chat Completions-compatibel JSON-antwoord. De provider ontvangt de opdracht, expliciete verwachtingen, zichtbare paginainhoud, elementlabels en testgeschiedenis. Screenshots worden lokaal opgeslagen. Het model kiest maximaal twaalf browseracties en controles. Verkeer buiten de ingestelde website-origin, WebSockets en HTTP-methodes buiten GET en HEAD zijn geblokkeerd. Formulieren die een POST nodig hebben kunnen daardoor alleen tot aan het verzendmoment worden getest. Gebruik een testomgeving waar GET-verzoeken en client-side acties veilig kunnen worden uitgevoerd.

Vul bij **Te controleren tekst** de exacte tekst in die tijdens de opgegeven flow zichtbaar of afwezig hoort te zijn. Via `POST /api/runs` kun je maximaal tien van deze regels meegeven als `expectations`, bijvoorbeeld `[{"condition":"text_visible","value":"1 artikel in winkelwagen","expected":true}]`. Een geverifieerde AI-fout vereist een afwijking van zo’n regel en een screenshot bij die controle. Afwijkingen van door het model voorgestelde verwachtingen verschijnen als **Te beoordelen**.

De demo gebruikt vaste Playwright-controles. De AI-modus kan ook wachten op zichtbare of afwezige tekst en een screenshot van de viewport of een aangeboden element maken. De modelprovider heeft standaard 25 seconden per antwoord. Stel desgewenst `LLM_TIMEOUT_MS` in om die grens te wijzigen. Bij een modeltimeout bevat het rapport de al uitgevoerde stappen. Draai `npm test` voor de demoflows en de AI-regressietests met een gesimuleerde modelprovider.

## Security Lab

Start de aparte oefenwebsite vanuit de projectmap met `npm run lab` en open [Security Lab](http://127.0.0.1:4327). De server luistert op het lokale loopbackadres en gebruikt fictieve accounts en dossiers. Kies de kwetsbare of herstelde variant om de doelpagina te openen.

Met `npm run lab:verify` start je een tijdelijke labserver en voer je de vaste controles uit. Het JSON-resultaat bevat verwachte en ontvangen waarden, reproduceerstappen en toepasselijke OWASP ASVS-verwijzingen. Het commando geeft een foutstatus als een uitkomst afwijkt van de bekende labresultaten.

| Proef | Kwetsbare variant | Herstelde variant |
| --- | --- | --- |
| Responseheaders | CSP en `nosniff` ontbreken | Beide headers zijn aanwezig |
| Cookie-attributen | Secure, HttpOnly en SameSite ontbreken | De drie attributen zijn aanwezig |
| Toegang tot een dossier | Bob ontvangt het fictieve dossier van Alice | Bob krijgt HTTP 403 |
| Sessie na afmelden | Het oude testtoken geeft nog toegang | Het oude testtoken geeft HTTP 401 |

De header- en cookieproeven gebruiken de bestaande passieve beveiligingsmodule. De dossier- en sessieproeven gebruiken uitsluitend de fictieve accounts van de tijdelijk gestarte labserver. De herstelvariant dient als referentie voor deze vier proeven.

### Lab bekijken in Browser Agent

Laat het lab in een eigen terminal draaien. Start Browser Agent in een tweede PowerShell-venster vanuit de projectmap met:

```powershell
$env:TEST_ORIGINS = 'http://127.0.0.1:4327'
node server.mjs
```

Plak `http://127.0.0.1:4327/vulnerable` of `http://127.0.0.1:4327/fixed` in het dashboard. Vink de toestemming en **Passieve beveiligingscontrole** aan. Deze route toont de headers en cookie-attributen met een screenshot van de pagina. Gebruik `npm run lab:verify` voor de dossier- en afmeldproeven.
