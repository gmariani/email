# Email Header Analyzer

Paste an email's source or drop an `.eml` / Outlook `.msg` file to see where it came from: every server it passed through (with a map), whether each link was encrypted, SPF/DKIM/DMARC results and alignment, the services involved (Amazon SES, Microsoft 365, Gmail, SendGrid…), and a plain-English explanation of every header.

For spam and phishing it shows **who actually sent it** (the account that logged in, the bounce address, the signer, the server that handed it to the recipient's provider) next to what the From line claims, and **where to report it**, in order: the sending service, the owner of the network it came from, the domain's registrar, then APWG.

The email is parsed **in the browser** and never uploaded. Only the relay IP addresses and host names found in its Received headers are sent to `api.php`, to look up reverse DNS and location.

| Data | Source |
| --- | --- |
| Route, authentication, headers, MIME parts | Parsed client-side from the message (`frontend/src/lib/`) |
| Reverse DNS, relay host names → IPs | Public resolvers, queried in parallel (`DNS_RESOLVERS`) |
| Live SPF, DKIM key, DMARC, reverse DNS, HELO and MX checks | Public resolvers, at the time you open the email (`app/Checks/`); DKIM signatures are then verified in the browser |
| Network owner and abuse contact | The Regional Internet Registry's RDAP record for the sending IP (looked up live) |
| Abuse contacts for sending services | `frontend/src/lib/data/services.ts` (`abuse`, `account`) |
| Geolocation | [ipinfo.io](https://ipinfo.io) while its quota lasts (`IP_INFO`), then the local [DB-IP Lite](https://db-ip.com/db/lite.php) database, ip-api.com only if that isn't installed |

## Layout

```
index.php  api.php   web entry points (page shell, JSON API)
app/                 server code (namespace EmailReader\), bootstrap.php, vendor/ and bin/. Not web-accessible.
  Relays/            what api.php does: validate the request, resolve, reverse-resolve, geolocate
  Http/ Geo/ Dns/    API + abuse guard, geolocation, parallel DNS client (shared design with Domain Inspector)
  Checks/            live checks: SPF evaluation (RFC 7208), DKIM keys, DMARC record, rDNS/HELO/MX
  Rdap/              network owner + abuse contact for an IP, from its Regional Internet Registry
  bin/locate.php     run a lookup from the CLI: php app/bin/locate.php 54.240.11.162 mx.google.com
                     (add --network for the owner and abuse contact)
  bin/update-geoip.php  download the DB-IP databases (run monthly)
frontend/src/
  lib/               the parser: message.ts (headers), received.ts (Received lines), route.ts (hops),
                     auth.ts (SPF/DKIM/DMARC/ARC), mime.ts (body parts, links), explain/ (per-header explanations),
                     sides.ts (where the recipient's side took over), sender.ts (who really sent it, where to report),
                     dkimVerify.ts (DKIM signature verification with Web Crypto), liveAuth.ts (live checks + DMARC)
  lib/data/          editable lists: services.ts (who adds which headers), headers.ts (what each header means)
  tabs/ components/  React UI
tests/               PHPUnit (tests/Unit) and the .eml fixtures the front-end tests read
storage/             caches, rate-limit counters, GeoIP databases (created at runtime)
scripts/package.mjs  builds dist/, the folder you upload
```

## Requirements

Server: PHP 8.1+ with curl and json, Apache. Outbound UDP/TCP 53 and HTTPS must be allowed.

Your machine: PHP + Composer and Node 20+, to build.

## Deploy

```sh
npm run package
```

Upload the **contents** of `dist/` to the site folder (e.g. `public_html/projects/email/`). It never contains `.env` or `storage/` data.

First deploy only:

1. Create `.env` next to `index.php` from `.env-sample`; fill in at least `GOOGLE_MAPS`, `IP_INFO` and `APP_URL`. Behind Cloudflare, also set `CLIENT_IP_HEADER=CF-Connecting-IP`.
2. Make sure `storage/` is writable by PHP.
3. Add the monthly GeoIP cron job (or point `GEOIP_CITY_DB` / `GEOIP_ASN_DB` at the Domain Inspector's copies to share them):
   ```
   0 4 3 * * /usr/local/bin/php /home/<user>/public_html/projects/email/app/bin/update-geoip.php > /dev/null
   ```

Check: the page loads, "Try an example" shows a route, and `…/app/bootstrap.php`, `…/storage/` and `…/.env` return 403.

## Development

In `.env` set `APP_ENV=development` and `VITE_DEV_SERVER=http://localhost:5173`, then run `npm run serve` (PHP on :8000) and `npm run dev` (Vite with hot reload).

## Teaching it new headers

- A new service (ESP, gateway, mailbox provider): add an entry to `frontend/src/lib/data/services.ts` with its header prefix, server host names, Message-ID and DKIM domains. Its headers are then grouped under its name. Add `abuse` (email and/or report form) and `account` (headers that identify the customer) so it appears under "Where to report it".
- A description for a header: `frontend/src/lib/data/headers.ts`.
- A header whose value can be decoded (like `X-Forefront-Antispam-Report` or `X-SES-Outgoing`): write an explainer in `frontend/src/lib/explain/` and add it to that file's map.

## Tests

```sh
npm test         # the parser, against the .eml files in tests/fixtures/
composer test    # PHP: request validation, IP helpers
```

## API protection

Same scheme as the Domain Inspector: `index.php` issues an HMAC token bound to a random secret in the visitor's session; `api.php` only accepts same-origin POSTs carrying it, and rate-limits per IP and per token. See `.env-sample`.
