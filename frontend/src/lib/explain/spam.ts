import { findHeader } from '../message';
import { fact, timeFacts, type Explainer, type Fact, type SpamRule } from './types';

/**
 * What SpamAssassin's rules mean, in plain words. Covers the standard rules
 * seen most often, plus a few widely installed add-ons (UCEPROTECT, iXhash,
 * KAM/PDS sets). Anything else is shown by name with a link to look it up.
 */
export const SPAMASSASSIN_TESTS: Record<string, string> = {
    // Bayesian filter: trained on this server's own mail
    BAYES_00: 'Bayesian filter: almost certainly not spam (0–1%)',
    BAYES_05: 'Bayesian filter: very unlikely spam (1–5%)',
    BAYES_20: 'Bayesian filter: unlikely spam (5–20%)',
    BAYES_40: 'Bayesian filter: probably not spam (20–40%)',
    BAYES_50: "Bayesian filter: can't tell (40–60%)",
    BAYES_60: 'Bayesian filter: possibly spam (60–80%)',
    BAYES_80: 'Bayesian filter: probably spam (80–95%)',
    BAYES_95: 'Bayesian filter: very likely spam (95–99%)',
    BAYES_99: 'Bayesian filter: almost certainly spam (99–100%)',
    BAYES_999: 'Bayesian filter: almost certainly spam (99.9–100%)',

    // Authentication
    DKIM_SIGNED: 'Has a DKIM signature (not necessarily valid)',
    DKIM_VALID: 'DKIM signature is valid',
    DKIM_VALID_AU: "DKIM signature is valid and from the author's (From) domain",
    DKIM_VALID_EF: "DKIM signature is valid and from the envelope sender's domain",
    DKIM_INVALID: "DKIM signature doesn't verify",
    T_DKIM_INVALID: "DKIM signature doesn't verify",
    DKIM_ADSP_NXDOMAIN: "The author's domain doesn't exist",
    DKIM_ADSP_ALL: "The author's domain says all its mail is signed, but this isn't validly signed",
    DKIM_ADSP_DISCARD: "The author's domain says to discard unsigned mail, and this isn't validly signed",
    NML_ADSP_CUSTOM_MED: 'Claims a domain that always signs its mail, but has no valid signature from it',
    SPF_PASS: 'SPF passed: the sending server is allowed to send for the envelope domain',
    SPF_FAIL: 'SPF failed: the envelope domain says this server may not send for it',
    SPF_SOFTFAIL: 'SPF soft fail: the envelope domain says this server probably may not send for it',
    SPF_NEUTRAL: 'SPF neutral: the envelope domain makes no claim about this server',
    SPF_NONE: "The envelope sender's domain has no SPF record",
    T_SPF_PERMERROR: "The envelope domain's SPF record is broken",
    T_SPF_TEMPERROR: 'The SPF check hit a temporary DNS error',
    SPF_HELO_PASS: 'SPF passed for the name the server introduced itself with (HELO)',
    SPF_HELO_NONE: 'The HELO name has no SPF record',
    SPF_HELO_NEUTRAL: 'SPF neutral for the HELO name',
    SPF_HELO_SOFTFAIL: 'SPF soft-failed for the HELO name',
    SPF_HELO_FAIL: 'SPF failed for the HELO name',
    T_SPF_HELO_PERMERROR: "The HELO name's SPF record is broken",
    T_SPF_HELO_TEMPERROR: 'The HELO SPF check hit a temporary DNS error',
    DMARC_PASS: 'DMARC passed',
    DMARC_NONE: 'DMARC failed; the domain asks for no action (p=none)',
    DMARC_QUAR: 'DMARC failed; the domain asks for it to go to spam (p=quarantine)',
    DMARC_REJECT: 'DMARC failed; the domain asks for it to be refused (p=reject)',
    DMARC_MISSING: "The From domain has no DMARC record",
    KAM_DMARC_STATUS: 'DMARC result check (KAM rule set)',
    KAM_DMARC_REJECT: 'DMARC failed for a domain with a reject policy (KAM rule set)',
    KAM_DMARC_QUARANTINE: 'DMARC failed for a domain with a quarantine policy (KAM rule set)',
    ARC_SIGNED: 'Has an ARC signature (passed through a forwarder or list)',
    ARC_VALID: 'ARC chain is valid',
    ARC_INVALID: "ARC chain doesn't verify",
    HEADER_FROM_DIFFERENT_DOMAINS: 'From and envelope sender are different domains',

    // Sending server and relays
    RDNS_NONE: 'The server that delivered it has no reverse DNS',
    RDNS_DYNAMIC: "The delivering server's name looks like a home or dynamic connection",
    HELO_DYNAMIC_IPADDR: 'The HELO name looks like a dynamic (home) IP address',
    HELO_NO_DOMAIN: "The HELO name isn't a domain",
    KHOP_HELO_FCRDNS: "The HELO name doesn't match the server's forward-confirmed reverse DNS",
    NO_RELAYS: 'No relays: delivered locally',
    NO_RECEIVED: 'No Received headers at all',
    ALL_TRUSTED: 'Passed only through trusted servers',
    UNPARSEABLE_RELAY: "A Received header couldn't be parsed",
    FORGED_GMAIL_RCVD: "Claims to come through Gmail, but the Received headers don't look like Gmail's",
    FORGED_YAHOO_RCVD: "Claims to come through Yahoo, but the Received headers don't look like Yahoo's",
    FORGED_MUA_OUTLOOK: "Claims to be sent from Outlook, but isn't formatted like Outlook",
    FORGED_OUTLOOK_HTML: "Claims to be from Outlook, but its HTML isn't Outlook's",
    SPOOFED_FREEMAIL: "Claims a free mailbox (Gmail, Yahoo…) but wasn't sent through it",

    // IP reputation and block lists
    RCVD_IN_DNSWL_NONE: 'Sender IP is on the DNSWL allow list, but with no trust',
    RCVD_IN_DNSWL_LOW: 'Sender IP is on the DNSWL allow list (low trust)',
    RCVD_IN_DNSWL_MED: 'Sender IP is on the DNSWL allow list (medium trust)',
    RCVD_IN_DNSWL_HI: 'Sender IP is on the DNSWL allow list (high trust)',
    RCVD_IN_DNSWL_BLOCKED: 'DNSWL lookup was refused (too many queries from this server)',
    RCVD_IN_MSPIKE_H2: 'Mailspike: average sender reputation',
    RCVD_IN_MSPIKE_H3: 'Mailspike: good sender reputation',
    RCVD_IN_MSPIKE_H4: 'Mailspike: very good sender reputation',
    RCVD_IN_MSPIKE_H5: 'Mailspike: excellent sender reputation',
    RCVD_IN_MSPIKE_WL: 'Sender IP is on the Mailspike allow list',
    RCVD_IN_MSPIKE_BL: 'Sender IP is on the Mailspike block list',
    RCVD_IN_MSPIKE_L2: 'Mailspike: poor sender reputation',
    RCVD_IN_MSPIKE_L3: 'Mailspike: bad sender reputation',
    RCVD_IN_MSPIKE_L4: 'Mailspike: very bad sender reputation',
    RCVD_IN_MSPIKE_L5: 'Mailspike: the worst sender reputation',
    RCVD_IN_ZEN_BLOCKED: 'Spamhaus lookup was refused (too many queries from this server)',
    RCVD_IN_ZEN_BLOCKED_OPENDNS: 'Spamhaus lookup was refused (it asked through a public resolver)',
    RCVD_IN_SBL: 'Sender IP is on the Spamhaus Block List (known spam source)',
    RCVD_IN_SBL_CSS: 'Sender IP is on the Spamhaus CSS list (snowshoe spam)',
    RCVD_IN_XBL: 'Sender IP is on the Spamhaus Exploits Block List (infected machine)',
    RCVD_IN_PBL: 'Sender IP is on the Spamhaus Policy Block List (a home connection that shouldn\'t send mail directly)',
    RCVD_IN_BL_SPAMCOP_NET: "Sender IP is on SpamCop's block list",
    RCVD_IN_PSBL: 'Sender IP is on the Passive Spam Block List',
    RCVD_IN_BARRACUDACENTRAL: "Sender IP is on Barracuda's reputation block list",
    RCVD_IN_SORBS_DUL: 'Sender IP is a dynamic (home) address according to SORBS',
    RCVD_IN_SORBS_SPAM: 'Sender IP was seen sending spam (SORBS)',
    RCVD_IN_SORBS_WEB: 'Sender IP is a hacked web server (SORBS)',
    RCVD_IN_UCEPROTECT1: 'Sender IP is on UCEPROTECT level 1: the IP itself was caught sending spam',
    RCVD_IN_UCEPROTECT2: "Sender IP is on UCEPROTECT level 2: its network has too many spamming IPs",
    RCVD_IN_UCEPROTECT3: "Sender IP is on UCEPROTECT level 3: its provider (whole ASN) has too many spamming IPs",
    RCVD_IN_VALIDITY_RPBL: "Sender IP is on Validity's reputation block list",
    RCVD_IN_VALIDITY_SAFE: "Sender IP is on Validity's safe list",
    RCVD_IN_VALIDITY_CERTIFIED: 'Sender IP is Validity-certified (a vetted bulk sender)',
    RCVD_IN_VALIDITY_RPBL_BLOCKED: 'Validity reputation lookup was refused',
    RCVD_IN_VALIDITY_SAFE_BLOCKED: 'Validity reputation lookup was refused',
    RCVD_IN_VALIDITY_CERTIFIED_BLOCKED: 'Validity reputation lookup was refused',
    RCVD_IN_RP_CERTIFIED: 'Sender IP is Return Path-certified (a vetted bulk sender)',
    RCVD_IN_RP_SAFE: "Sender IP is on Return Path's safe list",
    RCVD_IN_RP_RNBL: "Sender IP is on Return Path's reputation block list",
    DCC_CHECK: 'Matches many identical messages in the DCC bulk-mail database',
    DCC_REPUT_00_12: 'DCC: the sender has a good reputation',
    DCC_REPUT_13_19: 'DCC: the sender has a poor reputation',
    DCC_REPUT_70_89: 'DCC: the sender mostly sends bulk mail',
    DCC_REPUT_90_94: 'DCC: the sender almost only sends bulk mail',
    DCC_REPUT_95_98: 'DCC: the sender sends nearly nothing but bulk mail',
    DCC_REPUT_99_100: 'DCC: the sender sends only bulk mail',
    PYZOR_CHECK: 'Listed in the Pyzor collaborative spam database',
    RAZOR2_CHECK: "Listed in the Vipul's Razor collaborative spam database",
    RAZOR2_CF_RANGE_51_100: 'Razor: more than 50% confident it is spam',
    RAZOR2_CF_RANGE_E8_51_100: 'Razor: more than 50% confident it is spam',
    GENERIC_IXHASH: 'Matches a spam fingerprint in the iXhash database',
    NIXSPAM_IXHASH: 'Matches a spam fingerprint in the NiX Spam iXhash database',
    TXREP: "Adjustment from this server's sender reputation history (TxRep)",
    AWL: "Adjustment from this sender's past scores here (auto-whitelist)",
    USER_IN_WHITELIST: "The sender is on this server's allow list",
    USER_IN_WELCOMELIST: "The sender is on this server's allow list",
    USER_IN_BLACKLIST: "The sender is on this server's block list",
    USER_IN_BLOCKLIST: "The sender is on this server's block list",
    USER_IN_DEF_WHITELIST: "The sender is on SpamAssassin's built-in allow list",
    USER_IN_DEF_DKIM_WL: "Validly signed by a domain on SpamAssassin's built-in allow list",
    SHORTCIRCUIT: 'Scanning stopped early on a definitive rule',

    // Links
    URIBL_BLOCKED: 'URIBL lookup was refused (too many queries from this server)',
    URIBL_BLACK: 'A link points to a domain on the URIBL black list',
    URIBL_GREY: 'A link points to a domain on the URIBL grey list (often bulk mail)',
    URIBL_RED: 'A link points to a domain on the URIBL red list (newly seen in spam)',
    URIBL_SBL: "A link's domain is hosted on an IP on the Spamhaus Block List",
    URIBL_SBL_A: "A link's domain resolves to an IP on the Spamhaus Block List",
    URIBL_DBL_SPAM: 'A link points to a domain on the Spamhaus Domain Block List (spam)',
    URIBL_DBL_PHISH: 'A link points to a domain on the Spamhaus Domain Block List (phishing)',
    URIBL_DBL_MALWARE: 'A link points to a domain on the Spamhaus Domain Block List (malware)',
    URIBL_DBL_BOTNETCC: 'A link points to a botnet control server (Spamhaus DBL)',
    URIBL_DBL_ABUSE_SPAM: 'A link points to a hacked site used for spam (Spamhaus DBL)',
    URIBL_DBL_ABUSE_PHISH: 'A link points to a hacked site used for phishing (Spamhaus DBL)',
    URIBL_DBL_ABUSE_MALW: 'A link points to a hacked site used for malware (Spamhaus DBL)',
    URIBL_DBL_ABUSE_REDIR: 'A link points to an abused redirector (Spamhaus DBL)',
    URIBL_ABUSE_SURBL: 'A link points to a domain listed by SURBL for abuse',
    URIBL_PH_SURBL: 'A link points to a domain listed by SURBL for phishing',
    URIBL_MW_SURBL: 'A link points to a domain listed by SURBL for malware',
    URIBL_CR_SURBL: 'A link points to a domain listed by SURBL for cracked sites',
    URI_PHISH: 'A link looks like phishing',
    URI_HEX: 'A link has a host name written as a hex-encoded IP address',
    URI_NOVOWEL: "A link's domain has a long run of letters with no vowels (random-looking)",
    URI_TRY_3LD: 'A link uses a "try" subdomain, common in spam',
    URI_WP_HACKED: "A link points inside a WordPress site's folders, typical of hacked sites",
    URI_WP_HACKED_2: "A link points inside a WordPress site's folders, typical of hacked sites",
    URI_WPADMIN: "A link points into a WordPress site's admin folder",
    URI_DOTEDU: 'A link points to a .edu site (often abused)',
    URI_GOOGLE_PROXY: "A link goes through Google's image proxy",
    GOOG_REDIR_NORDNS: 'A link goes through a Google redirect, from a server with no reverse DNS',
    NORMAL_HTTP_TO_IP: 'A link points straight to an IP address instead of a domain',
    NUMERIC_HTTP_ADDR: 'A link points straight to an IP address instead of a domain',
    WEIRD_PORT: 'A link uses an unusual port number',
    HTTPS_HTTP_MISMATCH: 'A link shows https:// but goes to a plain http:// address',
    SHORT_SHORTNER: 'Short message with a URL-shortener link',
    URI_SHORTENER: 'A link uses a URL shortener, hiding where it goes',
    PDS_OTHER_BAD_TLD: 'A link points to a top-level domain with a lot of abuse',
    PDS_SHORTFWD_URISHRT_QP: 'Short forwarded message with a URL-shortener link',
    T_REMOTE_IMAGE: 'Loads images from another server (they can tell when it\'s opened)',

    // Headers
    MISSING_MID: 'No Message-ID',
    MISSING_DATE: 'No Date header',
    MISSING_HEADERS: 'No To header',
    MISSING_FROM: 'No From header',
    MISSING_SUBJECT: 'No Subject',
    INVALID_DATE: "The Date header isn't a valid date",
    INVALID_MSGID: "The Message-ID isn't valid",
    MSGID_FROM_MTA_HEADER: "The Message-ID was added by a server, not the sender's mail app",
    DATE_IN_PAST_03_06: 'The Date header is 3 to 6 hours before it was received',
    DATE_IN_PAST_06_12: 'The Date header is 6 to 12 hours before it was received',
    DATE_IN_PAST_12_24: 'The Date header is 12 to 24 hours before it was received',
    DATE_IN_PAST_24_48: 'The Date header is 1 to 2 days before it was received',
    DATE_IN_PAST_96_XX: 'The Date header is more than 4 days before it was received',
    DATE_IN_FUTURE_03_06: 'The Date header is 3 to 6 hours in the future',
    DATE_IN_FUTURE_06_12: 'The Date header is 6 to 12 hours in the future',
    DATE_IN_FUTURE_12_24: 'The Date header is 12 to 24 hours in the future',
    DATE_IN_FUTURE_96_XX: 'The Date header is more than 4 days in the future',
    FREEMAIL_FROM: 'Sent from a free mailbox provider (Gmail, Yahoo…)',
    FREEMAIL_ENVFROM_END_DIGIT: 'The envelope sender is a free mailbox ending in a digit',
    FREEMAIL_REPLYTO: 'Reply-To is a free mailbox',
    FREEMAIL_REPLYTO_END_DIGIT: 'Reply-To is a free mailbox ending in a digit',
    FREEMAIL_FORGED_REPLYTO: 'Reply-To is a different free mailbox than From',
    FREEMAIL_FORGED_FROMDOMAIN: 'The From name mentions a free mailbox domain that differs from the address',
    FROM_EXCESS_BASE64: "The From name is base64-encoded although it doesn't need to be",
    FROM_LOCAL_HEX: 'The From address is a long string of hex digits',
    FROM_LOCAL_NOVOWEL: 'The From address has no vowels (random-looking)',
    FROM_LOCAL_DIGITS: 'The From address is mostly digits',
    FROM_STARTS_WITH_NUMS: 'The From address starts with several digits',
    FROM_ADDR_WS: 'The From address contains spaces',
    FROM_SUSPICIOUS_NTLD: 'The From domain uses a top-level domain with a lot of abuse',
    FROM_SUSPICIOUS_NTLD_FP: 'The From domain uses a top-level domain with a lot of abuse',
    FROM_FMBLA_NEWDOM: 'The From domain was registered in the last week',
    FROM_FMBLA_NEWDOM14: 'The From domain was registered in the last two weeks',
    FROM_FMBLA_NEWDOM28: 'The From domain was registered in the last four weeks',
    NO_DNS_FOR_FROM: 'The From domain has no DNS records',
    HK_RANDOM_FROM: 'The From address looks randomly generated',
    HK_RANDOM_ENVFROM: 'The envelope sender looks randomly generated',
    HK_RANDOM_REPLYTO: 'The Reply-To address looks randomly generated',
    HK_NAME_FREE: 'The From name looks like a free-mail address',
    PDS_FROM_2_EMAILS: 'The From line contains two different email addresses',
    TO_EQ_FM_DIRECT_MX: 'To and From are the same address and it was sent straight to the mail server',
    TO_EQ_FM_DOM_SPF_FAIL: 'To and From are the same domain, and SPF failed',
    TO_NO_BRKTS_PCNT: 'To address without angle brackets, with a percent sign',
    TO_NO_BRKTS_HTML_ONLY: 'To address without angle brackets, and an HTML-only message',
    REPLYTO_WITHOUT_TO_CC: 'Has a Reply-To but no To or Cc',
    SUBJ_ALL_CAPS: 'Subject is all capital letters',
    SUBJ_ILLEGAL_CHARS: 'Subject contains raw non-ASCII characters without encoding',
    SUBJ_OBFU_PUNCT_FEW: 'Subject has punctuation inserted inside words (to dodge filters)',
    SUBJ_OBFU_PUNCT_MANY: 'Subject has lots of punctuation inserted inside words (to dodge filters)',
    LOCALPART_IN_SUBJECT: "The subject contains the recipient's user name",
    CHARSET_FARAWAY_HEADER: 'A header uses a character set for a language far from yours',
    XPRIO: 'Has an X-Priority header, common in bulk mail',
    XPRIO_SHORT_SUBJ: 'Has an X-Priority header and a very short subject',

    // Body and formatting
    HTML_MESSAGE: 'Contains HTML',
    MIME_HTML_ONLY: 'HTML only, no plain-text version',
    MIME_HTML_MOSTLY: 'Mostly HTML',
    MIME_HTML_ONLY_MULTI: 'Several parts, all HTML',
    MPART_ALT_DIFF: 'The plain-text and HTML versions say noticeably different things',
    MPART_ALT_DIFF_COUNT: 'The plain-text and HTML versions have different numbers of words',
    MIME_QP_LONG_LINE: 'A quoted-printable line is longer than the standard allows',
    MIME_BASE64_TEXT: 'Text is base64-encoded although it doesn\'t need to be (hides it from simple filters)',
    MIME_HEADER_CTYPE_ONLY: 'Only a Content-Type header, no MIME-Version',
    MIME_BOUND_DIGITS_15: 'MIME boundary is a long string of digits (spam software)',
    CTE_8BIT_MISMATCH: 'Declared as 7-bit but contains 8-bit characters',
    BODY_8BITS: 'Body has runs of non-ASCII (8-bit) characters',
    HTML_IMAGE_ONLY_04: 'HTML with images and almost no text (under 400 bytes)',
    HTML_IMAGE_ONLY_08: 'HTML with images and almost no text (under 800 bytes)',
    HTML_IMAGE_ONLY_12: 'HTML with images and very little text (under 1200 bytes)',
    HTML_IMAGE_ONLY_16: 'HTML with images and little text (under 1600 bytes)',
    HTML_IMAGE_ONLY_20: 'HTML with images and little text (under 2000 bytes)',
    HTML_IMAGE_ONLY_24: 'HTML with images and little text (under 2400 bytes)',
    HTML_IMAGE_ONLY_28: 'HTML with images and little text (under 2800 bytes)',
    HTML_IMAGE_RATIO_02: 'HTML has very little text compared with its images',
    HTML_IMAGE_RATIO_04: 'HTML has little text compared with its images',
    HTML_IMAGE_RATIO_06: 'HTML has little text compared with its images',
    HTML_IMAGE_RATIO_08: 'HTML has somewhat little text compared with its images',
    HTML_SHORT_LINK_IMG_1: 'Short HTML message that is mostly a linked image',
    HTML_SHORT_LINK_IMG_2: 'Short HTML message that is mostly a linked image',
    HTML_SHORT_LINK_IMG_3: 'Short HTML message that is mostly a linked image',
    HTML_FONT_LOW_CONTRAST: 'Text in a colour close to the background (hidden text)',
    HTML_FONT_SIZE_LARGE: 'Uses a very large font',
    HTML_FONT_SIZE_HUGE: 'Uses a huge font',
    HTML_MIME_NO_HTML_TAG: 'HTML part with no <html> tag',
    HTML_TAG_BALANCE_BODY: "The HTML's tags don't match up (malformed HTML)",
    HTML_OBFUSCATE_05_10: 'HTML hides words by splitting them up (5–10%)',
    HTML_OBFUSCATE_10_20: 'HTML hides words by splitting them up (10–20%)',
    HTML_OBFUSCATE_20_30: 'HTML hides words by splitting them up (20–30%)',
    T_KAM_HTML_FONT_INVALID: 'HTML has an invalid font tag',
    T_SCC_BODY_TEXT_LINE: 'Body has a line of text (informational)',
    TVD_SPACE_RATIO: 'Unusual spacing between characters',
    EMPTY_MESSAGE: 'The message has no text',
    ENCRYPTED_MESSAGE: 'The message is encrypted',
    UNWANTED_LANGUAGE_BODY: "Written in a language this server is set to treat as unwanted",

    // Content
    LOTS_OF_MONEY: 'Mentions large amounts of money',
    MONEY_NOHTML: 'Talks about money, plain text only',
    MONEY_FROM_MISSP: 'Talks about money, and the From name is misspelled',
    MONEY_FREEMAIL_REPTO: 'Talks about money and asks for replies to a free mailbox',
    ADVANCE_FEE_2_NEW_MONEY: 'Advance-fee (419) scam wording',
    ADVANCE_FEE_3_NEW_MONEY: 'Advance-fee (419) scam wording',
    ADVANCE_FEE_4_NEW_MONEY: 'Advance-fee (419) scam wording',
    ADVANCE_FEE_5_NEW_MONEY: 'Advance-fee (419) scam wording',
    FILL_THIS_FORM: 'Asks you to fill in a form with your details',
    FILL_THIS_FORM_LONG: 'Asks you to fill in a long form with your details',
    T_FILL_THIS_FORM_SHORT: 'Asks you to fill in a short form with your details',
    DEAR_SOMETHING: 'Starts with "Dear …" rather than your name',
    PDS_BTC_ID: 'Contains a Bitcoin address',
    BITCOIN_EXTORT_01: 'Bitcoin extortion wording ("I recorded you…")',
    ACCT_PHISHING: 'Account phishing wording ("verify your account")',
    FUZZY_CREDIT: 'A disguised spelling of "credit"',
    FUZZY_MILLION: 'A disguised spelling of "million"',
};

export function testLabel(name: string): string {
    return SPAMASSASSIN_TESTS[name.toUpperCase()] ?? '';
}

/**
 * A web search for the rule: SpamAssassin has no page per rule (its Rule QA
 * site is offline), and a search also finds custom and Rspamd rules.
 */
export function ruleUrl(name: string, engine = 'spamassassin'): string {
    return `https://duckduckgo.com/?q=${encodeURIComponent(`"${name}" ${engine}`)}`;
}

/** "BAYES_00,DKIM_SIGNED=0.1", "[AWL, BAYES_50,\n HTML_MESSAGE]" => [name, points?] pairs. */
export function parseRuleList(text: string): [string, number | null][] {
    return text
        .replace(/^\s*\[|\]\s*$/g, '')
        .split(/[\s,]+/)
        .filter(Boolean)
        .map((part) => {
            const [name, points] = part.split('=');
            const value = points !== undefined ? parseFloat(points) : NaN;
            return [name, Number.isNaN(value) ? null : value];
        });
}

/** X-Spam-Report lines: "* -0.1 DKIM_VALID Message has at least one valid DKIM…" */
function reportLines(text: string): { name: string; points: number; description: string }[] {
    const out: { name: string; points: number; description: string }[] = [];
    for (const m of text.matchAll(/\*\s+(-?[\d.]+)\s+([A-Z0-9_]+)\s+(.*?)(?=\s+\*\s+-?[\d.]+\s+[A-Z0-9_]+\s|$)/gs)) {
        out.push({ name: m[2], points: parseFloat(m[1]), description: m[3].replace(/\s*\*\s+/g, ' ').replace(/\s+/g, ' ').trim() });
    }
    return out;
}

/**
 * The table rows for SpamAssassin rules. The server's own descriptions
 * (from X-Spam-Report, when it added one) fill in rules this page doesn't know.
 */
function saRules(list: [string, number | null][], reported: Map<string, string>): SpamRule[] {
    return list.map(([name, points]) => ({
        name,
        points,
        meaning: testLabel(name) || reported.get(name.toUpperCase()) || null,
        url: ruleUrl(name),
    }));
}

function reportedDescriptions(headers: Parameters<Explainer>[1]['headers']): Map<string, string> {
    const report = findHeader(headers, 'x-spam-report');
    return new Map(report ? reportLines(report.value).map((l) => [l.name.toUpperCase(), l.description]) : []);
}

/** X-Spam-Status: No, score=-2.1 required=5.0 tests=BAYES_00,DKIM_SIGNED autolearn=ham version=3.4.6 */
export const spamStatus: Explainer = (field, context) => {
    const v = field.value;
    const isSpam = /^\s*yes\b/i.test(v);
    // Short form some installs use: "No/-0.1/5.0" (verdict/score/threshold).
    const short = /^\s*(?:yes|no)\/(-?[\d.]+)\/(-?[\d.]+)/i.exec(v);
    const score = short?.[1] ?? /(?:score|hits)=(-?[\d.]+)/i.exec(v)?.[1];
    const required = short?.[2] ?? /required=(-?[\d.]+)/i.exec(v)?.[1];
    // tests=A,B,C or (amavis) tests=[A, B, C]
    const testsText = /tests=(\[[^\]]*\]|.*?)(?:\s+\w+=|$)/is.exec(v)?.[1] ?? '';
    const autolearn = /autolearn=(\S+)/i.exec(v)?.[1];
    const version = /version=(\S+)/i.exec(v)?.[1];
    const facts: Fact[] = [
        { label: 'Verdict', value: isSpam ? 'Spam' : 'Not spam', tone: isSpam ? 'bad' : 'good' },
        ...fact('Score', score && required ? `${score} (spam at ${required} or more)` : score),
        ...fact('Auto-learn', autolearn, { hint: 'Whether the Bayesian filter learned from this message (ham = not spam).', tone: 'muted' }),
        ...fact('SpamAssassin version', version, { tone: 'muted' }),
    ];
    return {
        summary: `SpamAssassin: ${isSpam ? 'spam' : 'not spam'}${score ? `, scored ${score}${required ? ` of ${required}` : ''}` : ''}.`,
        facts,
        rules: saRules(parseRuleList(testsText), reportedDescriptions(context.headers)),
    };
};

/** "DKIM_SIGNED=0.1,DKIM_VALID=-0.1,…": each rule that matched and its points. */
const testScores: Explainer = (field, context) => {
    const rules = saRules(parseRuleList(field.value), reportedDescriptions(context.headers));
    const total = rules.reduce((sum, r) => sum + (r.points ?? 0), 0);
    return {
        summary: `${rules.length} SpamAssassin rule${rules.length === 1 ? '' : 's'} matched, adding up to ${Math.round(total * 1000) / 1000} points.`,
        facts: [],
        rules,
    };
};

/** X-Spam-Report: "* -0.1 DKIM_VALID Message has at least one valid DKIM…" per line. */
const spamReport: Explainer = (field) => {
    const lines = reportLines(field.value);
    if (!lines.length) return null;
    return {
        summary: 'Each rule SpamAssassin matched, with its points.',
        facts: [],
        rules: lines.map((l) => ({ name: l.name, points: l.points, meaning: testLabel(l.name) || l.description, url: ruleUrl(l.name) })),
    };
};

export const spamScore: Explainer = (field) => ({ facts: fact('Score', field.value.trim()) });

export const spamLevel: Explainer = (field) => {
    const stars = (field.value.match(/[*+]/g) ?? []).length;
    return { facts: fact('Score', `${stars} point${stars === 1 ? '' : 's'} or more`) };
};

export const spamFlag: Explainer = (field) => {
    const yes = /^\s*yes/i.test(field.value);
    return { facts: [{ label: 'Flagged as spam', value: yes ? 'Yes' : 'No', tone: yes ? 'bad' : 'good' }] };
};

/** X-Spamd-Result: default: False [-1.20 / 15.00]; ARC_NA(0.00)[]; DMARC_POLICY_ALLOW(-0.50)[example.com,reject]; … */
export const rspamdResult: Explainer = (field) => {
    const head = /^\s*(\w+):\s*(True|False)\s*\[\s*(-?[\d.]+)\s*\/\s*(-?[\d.]+)\s*\]/i.exec(field.value);
    const facts: Fact[] = [];
    if (head) {
        const spam = head[2].toLowerCase() === 'true';
        facts.push({ label: 'Verdict', value: spam ? 'Spam' : 'Not spam', tone: spam ? 'bad' : 'good' });
        facts.push({ label: 'Score', value: `${head[3]} (reject at ${head[4]})` });
    }
    // SYMBOL(points)[details]: Rspamd has no per-symbol pages, so the details it gives are the meaning.
    const rules: SpamRule[] = [...field.value.matchAll(/([A-Z0-9_]+)\((-?[\d.]+)\)(?:\[([^\]]*)\])?/g)].map((m) => ({
        name: m[1],
        points: parseFloat(m[2]),
        meaning: [testLabel(m[1]), m[3] ? `details: ${m[3]}` : ''].filter(Boolean).join('; ') || null,
        url: ruleUrl(m[1], 'rspamd'),
    }));
    return { summary: head ? `Rspamd: ${head[2].toLowerCase() === 'true' ? 'spam' : 'not spam'}, score ${head[3]} of ${head[4]}.` : undefined, facts, rules };
};

export const rspamdAction: Explainer = (field) => {
    const action = field.value.trim().toLowerCase();
    const tone = action === 'no action' ? 'good' : action === 'reject' ? 'bad' : 'warn';
    return { facts: [{ label: 'Action', value: field.value.trim(), tone }] };
};

export const virusStatus: Explainer = (field) => {
    const clean = /^\s*(clean|no)\b/i.test(field.value);
    const infected = /infected|yes|virus/i.test(field.value) && !clean;
    return { facts: [{ label: 'Virus scan', value: field.value.trim(), tone: infected ? 'bad' : clean ? 'good' : undefined }] };
};

/** X-Barracuda-Spam-Status: No, SCORE=0.00 using global scores of TAG_LEVEL=3.5 QUARANTINE_LEVEL=1000.0 KILL_LEVEL=5.0 tests=… */
export const barracudaStatus: Explainer = (field) => {
    const isSpam = /^\s*yes\b/i.test(field.value);
    const score = /SCORE=(-?[\d.]+)/i.exec(field.value)?.[1];
    const kill = /KILL_LEVEL=(-?[\d.]+)/i.exec(field.value)?.[1];
    const tag = /TAG_LEVEL=(-?[\d.]+)/i.exec(field.value)?.[1];
    const tests = /tests=([^\s]*)/i.exec(field.value)?.[1]?.split(',').filter(Boolean) ?? [];
    return {
        summary: `Barracuda: ${isSpam ? 'spam' : 'not spam'}${score ? `, score ${score}` : ''}.`,
        facts: [
            { label: 'Verdict', value: isSpam ? 'Spam' : 'Not spam', tone: isSpam ? 'bad' : 'good' },
            ...fact('Score', score),
            ...fact('Tagged at', tag),
            ...fact('Blocked at', kill),
        ],
        // Barracuda's rules are mostly SpamAssassin's.
        rules: tests.map((name) => ({ name, points: null, meaning: testLabel(name) || null, url: ruleUrl(name, 'barracuda') })),
    };
};

export const barracudaStartTime: Explainer = (field) => {
    const seconds = parseInt(field.value, 10);
    return Number.isNaN(seconds) ? null : { facts: timeFacts('Scanned at', seconds * 1000) };
};

/** X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 … */
export const proofpointDetails: Explainer = (field) => {
    const facts: Fact[] = [];
    const rule = /rule=(\S+)/.exec(field.value)?.[1];
    if (rule) facts.push({ label: 'Rule', value: rule, tone: /notspam|safe/i.test(rule) ? 'good' : /spam|phish|bulk|malware/i.test(rule) ? 'bad' : undefined });
    for (const [, key, value] of field.value.matchAll(/\b(policy|score|spamscore|phishscore|malwarescore|bulkscore|adultscore|suspectscore|impostorscore|priorityscore|lowpriorityscore|clxscore|mlxscore|mlxlogscore)=(\S+)/g)) {
        facts.push({ label: key, value, tone: /score$/.test(key) && parseInt(value, 10) >= 50 && key !== 'clxscore' ? 'warn' : undefined });
    }
    return { summary: rule ? `Proofpoint classified it as "${rule}".` : undefined, facts };
};

export const mimecastScore: Explainer = (field) => ({ facts: fact('Spam score', field.value.trim(), { hint: 'Mimecast spam score; higher is spammier.' }) });

// ----------------------------------------------------------------- OVH

/**
 * OVH's X-VR-SPAMCAUSE is lightly scrambled: two letters per character, their codes summed,
 * minus "x", minus 16 for each step a letter c–h is from "g". Algorithm as decoded in
 * decode-spam-headers by Mariusz Banach (github.com/mgeeky/decode-spam-headers, MIT licence).
 */
export function decodeSpamcause(value: string): string | null {
    const text = value.replace(/\s+/g, '');
    if (!/^[a-z]+$/i.test(text) || text.length % 2) return null;
    let out = '';
    for (let i = 0; i < text.length; i += 2) {
        const pair = text.slice(i, i + 2);
        const shifted = [...'cdefgh'].find((c) => pair.includes(c));
        const offset = shifted ? ('g'.charCodeAt(0) - shifted.charCodeAt(0)) * 16 : 0;
        out += String.fromCharCode(pair.charCodeAt(0) + pair.charCodeAt(1) - 'x'.charCodeAt(0) - offset);
    }
    return /^[\x20-\x7e\t\r\n]*$/.test(out) ? out : null;
}

const spamcause: Explainer = (field) => {
    const decoded = decodeSpamcause(field.value);
    if (!decoded) return { facts: [{ label: 'Contents', value: "Couldn't be decoded", tone: 'muted', hint: 'Not in the scrambled form OVH normally uses. The full text is under Raw header.' }] };
    const parts = decoded.split(';').map((p) => p.trim()).filter(Boolean);
    return {
        summary: 'OVH spam filter reasons, unscrambled.',
        facts: parts.map((part) => {
            const m = /^([\w.-]+)\s*[:=]\s*(.*)$/.exec(part);
            return m ? { label: m[1], value: m[2], mono: true } : { label: 'Reason', value: part, mono: true };
        }),
        help: "OVH scrambles its spam filter's reasons in this header; this is the unscrambled text. OVH doesn't document the individual fields.",
    };
};

export const SPAM: Record<string, Explainer> = {
    'x-vr-spamcause': spamcause,
    'x-spam-status': spamStatus,
    'x-spam-score': spamScore,
    'x-spam-test-scores': testScores,
    'x-spam-report': spamReport,
    'x-spam-last-external-ip': (field) => ({ facts: fact('Last outside server', field.value.trim(), { kind: 'ip', hint: 'The last server before your provider, as SpamAssassin saw it.' }) }),
    'x-spam-last-external-helo': (field) => ({ facts: fact('Its HELO name', field.value.trim()) }),
    'x-spam-last-external-rdns': (field) => ({ facts: fact('Its reverse DNS', field.value.trim()) }),
    'x-spam-date-of-scan': (field) => ({ facts: fact('Scanned at', field.value.trim()) }),
    'x-spam-level': spamLevel,
    'x-spam-flag': spamFlag,
    'x-spamd-result': rspamdResult,
    'x-rspamd-action': rspamdAction,
    'x-rspamd-score': spamScore,
    'x-virus-status': virusStatus,
    'x-virus-scanned': (field) => ({ facts: fact('Scanned by', field.value) }),
    'x-barracuda-spam-status': barracudaStatus,
    'x-barracuda-spam-score': spamScore,
    'x-barracuda-start-time': barracudaStartTime,
    'x-proofpoint-spam-details': proofpointDetails,
    'x-mimecast-spam-score': mimecastScore,
};
