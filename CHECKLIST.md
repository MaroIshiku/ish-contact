# Abnahme-Check

Stand: 2026-06-20

## Architektur

- Python-Server liefert die PWA und speichert nur den verschluesselten Token.
- Clientseitige Verschluesselung bleibt vollstaendig im Browser.
- Dockerfile und `docker-compose.yml` fuer ZimaOS/Reverse-Proxy-Betrieb vorhanden.
- Persistenz erfolgt ueber Docker-Volume `/data`.
- App-Icon/Logo ist als SVG und PNG-Favicon eingebunden.

## Sicherheit

- `POST /api/token` und Legacy `POST /save.php` benoetigen `X-Auth-Token`.
- Ohne `DV2_SHARED_SECRET` startet der Container nicht.
- Token-Write ist atomar und auf 1 MB Request-Groesse begrenzt.
- Token wird auf Mindestlaenge und erlaubte Zeichen geprueft.
- Server setzt grundlegende Security-Header.
- Service Worker cached keine Token-/Save-Endpunkte.
- Container laeuft als non-root User.

## Funktionen

- Setup speichert verschluesselte Daten ueber die Python-API.
- Login per Master-Passwort bleibt erhalten.
- PIN speichert nur einen lokal verschluesselten Passwort-Blob.
- Passkey/WebAuthn-PRF bleibt optional erhalten.
- Privat-, Firma-, PayPal- und Bank-Reiter bleiben erhalten.
- QR-Codes werden lokal erzeugt.
- vCard enthaelt nur private Felder.
- PayPal-Link enthaelt keinen Verwendungszweck.
- GiroCode enthaelt optionalen Verwendungszweck.
- Betrag synchronisiert zwischen PayPal und Bank.
- Export/Import des Tokens bleibt erhalten.

## Deployment

- `docker compose up -d --build` baut und startet den Container.
- Healthcheck prueft `GET /healthz`.
- Reverse Proxy muss HTTPS terminieren.
- `.env` enthaelt `DV2_SHARED_SECRET`; `.env` wird nicht versioniert.
