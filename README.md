# Browser Agent

Lokaal dashboard voor website-QA. De demo gebruikt Playwright met Microsoft Edge en heeft geen API-sleutel nodig.

## Starten

Voer dit vanuit de projectmap uit met Node.js 22 of hoger en Microsoft Edge geïnstalleerd.

```powershell
npm ci
npm start
```

Open [het dashboard](http://127.0.0.1:4317). Kies **Demo met fout**, vink de toestemming aan en klik op **Start AI-test**. De vijf scenario’s zijn zoeken, categorieën filteren, productdetails openen, toevoegen aan de winkelwagen en de betaalstap bereiken. De muis activeert in de foutdemo een bug. Het toetsenbord kan wel in de winkelwagen, zodat de betaalstap apart kan worden getest. **Werkende demo** gebruikt dezelfde browsercontroles en de variant met een werkende winkelwagen.

Rapporten en screenshots staan per test in `runs/<id>/`. Het JSON-rapport bevat URL’s naar de screenshots op de lokale server.

## Eigen testsite aansluiten

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
