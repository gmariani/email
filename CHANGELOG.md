# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [20261102]
### Changed
- Outlook `.msg` files are read in full instead of headers only: the plain-text body, the HTML body (taken from Outlook's own copy, or unwrapped from the RTF body it keeps for HTML mail), inline images, attachments and attached Outlook items are rebuilt into a MIME message, so the Content tab, links and attachments work as for `.eml`. Attached items with no internet headers get From, To, Subject and Date from Outlook's own fields.
- DKIM body hashes aren't checked for a body rebuilt from a `.msg` (it can't match what was signed); the Authentication tab says why instead of reporting the body as altered.

## [20261026]
### Added
- "Who sent it": what the From line claims next to what the headers show (logged-in account, envelope sender, DKIM signer, sending-service account ids, the server that handed the message to the recipient's provider), with mismatches flagged.
- "Where to report it": the sending service's abuse contact (with the ids to quote), the network owner's abuse address looked up live from the regional internet registry, the domain's registrar, and APWG. The recipient's own provider is never suggested.
- Authentication summary on the Summary tab and at the top of the Authentication tab, with a plain-English verdict. Each card says what the check proved (which server may send for which domain, who signed it); alignment with From is only shown once a check passed. When the receiver recorded nothing, results from ARC-Authentication-Results are used and labelled as such.
- Live checks on the Authentication tab, one section per technology, each next to what the receiving server recorded:
  - SPF: the sender's record, evaluated for the sending IP (includes, redirects, macros, the 10-lookup limit) with a trace of which term matched.
  - DKIM: each signature verified in the browser against the key published in DNS (RSA and Ed25519), with the key's type and size and a clear explanation when only the body differs.
  - DMARC: the record, its validity and every tag explained, warnings for p=none, missing rua, partial pct and unauthorised external report addresses, and a DMARC verdict from the live results.
  - Reverse DNS: forward-confirmed reverse DNS and HELO name for the sending server; MX records for the sender's domains in their own section.
- Headers tab: one table in message order with a Group column and a group filter; each header's raw text is folded away under its plain-English reading.
- Authentication headers explained one line per part: every Authentication-Results property and comment (header.b, dkim-atps, p=/dis=, key size…), Received-SPF fields, DKIM/ARC/DomainKey tags, SpamAssassin rule lists and reports.
- Recognises Zoho ZeptoMail and Campaigns, Eventbrite, SparkPost's X-MSYS-API metadata, OpenDMARC/OpenDKIM stamps and more Exchange Online headers; "Who sent it" shows the Microsoft 365 organisation (X-OriginatorOrg).
- Disguised text: letters from other alphabets that pass for Latin ones (Cyrillic "Ѕtоrаgе"), styled Unicode letters, invisible characters and punycode (xn--) domains are detected in the From, Reply-To and Sender names and addresses, the envelope sender, the subject and link domains. The Summary says what each one really reads as, and the letters are highlighted in the title (hover for which character each one is).
- Recorded results that don't hold up are flagged: a DKIM pass for a domain with no signature in the message, or a pass in ARC/X-Original headers (written by a server along the way, often the sender's) that fails when checked now. The headline becomes "Unproven", the cards and "Who sent it" use what checks out now, and the recorded claim is shown with a warning. Recorded passes from the receiving server's own headers that fail now are noted more gently (DNS may have changed since).
- Spam-filter rules (X-Spam-Status, X-Spam-Test-Scores, X-Spam-Report, Rspamd, Barracuda) are shown as a Rule / Points / What it means table with a total, a web-search link per rule, and plain-English descriptions for over 260 common SpamAssassin rules. Rules this page doesn't know take the server's own description from X-Spam-Report when there is one.
- A rejected Google Maps key now shows a message instead of a broken map.
- Initial version, built on the Domain Inspector's structure (PHP API + React front-end).
- Paste, drop or open `.eml`, `.msg` (headers only) and plain-text email sources; parsed entirely in the browser.
- Route: each Received header parsed (Exim, Postfix, Sendmail, Exchange, Gmail and others), shown as a flow with the encryption, TLS version, protocol, server software and delay of every link, plus a map of the relays.
- Authentication: SPF, DKIM, DMARC and ARC results, with alignment against the From domain.
- Headers: every header explained and grouped by the service that added it (Amazon SES, Microsoft 365, Google, SendGrid, Mailgun, Proofpoint, SpamAssassin, cPanel…). Decodes SES message-id timestamps and Feedback-ID regions, Exchange anti-spam reports, SpamAssassin/Rspamd verdicts and Outlook Thread-Index.
- Checked against real messages: older Exim TLS notation (`TLSv1:CIPHER:256`), IIS SMTPSVC and its pickup service, filtering gateways that re-inject mail internally, electric.net and X-OriginalArrivalTime headers. Obsolete TLS (1.0/1.1) and logins over unencrypted connections are flagged; unencrypted hops inside a private network are reported separately.
- Content: MIME structure, attachments (downloadable; attached emails can be analysed), links with mismatched text, and a preview that blocks scripts and remote images.

### Fixed
- When no server recorded SPF, DKIM or DMARC results (common behind gateways that don't add Authentication-Results), the summary said "Not checked" even though the live checks passed. Gaps are now filled from the live checks; results a server did record still take priority. Each card lists both sources ("In the email" and "Live check"). "Who sent it" uses the same results.
- The sending server was misidentified when the sender's own Exchange server relayed to itself (exch01 → exch01): the handoff stopped on that private hop, so SPF and reverse DNS weren't checked. Only a loop on the receiving side is now skipped.
- DKIM body hashes failed for files saved with extra blank lines between the headers and the body (several mail apps do this). Those lines are ignored when that makes the hash match, and the verification says so.
- X-Spam-Status rule lists in Amavis' bracketed form (`tests=[AWL, BAYES_50, …]`) kept the brackets on the first and last rule names.
- DKIM results recorded with a bare `header.i=example.com` (Zoho) lost their domain ("Signed by ;").
- DKIM signature details are a Tag / Value / Meaning table like DMARC's, including bh= and b=.
- Route: a server known by an internal name (exch01.ELWOOD.local, 10.0.3.25) but seen by the next server under a public one (hybrid.example.com, 66.244.119.124) is now shown under the public name, with the internal one underneath. The sending server (the last one outside the recipient's provider) is labelled, and the hop count says how many hops were between servers and how many inside one.
- A gateway passing mail through its own content filter ("by localhost", e.g. amavis on port 10024) was mistaken for the sending server, so SPF was checked against the gateway's IP instead of the real sender's. Those loops now count as the same machine, and the route shows them inside the gateway's step.
