/**
 * What each header is for, in plain English. Keys are lower case. Headers
 * that belong to one service (X-SES-*, X-MS-*…) are grouped under that service
 * on the Headers tab (see services.ts); the category is used otherwise.
 *
 * Patterns at the bottom cover families of headers (X-MS-Exchange-*, ARC-*…)
 * that would be tedious to list one by one.
 */

export type Category = 'identity' | 'message' | 'routing' | 'auth' | 'content' | 'list' | 'client' | 'spam' | 'other';

export const CATEGORY_TITLES: Record<Category, string> = {
    identity: 'Sender & recipients',
    message: 'Message details',
    routing: 'Delivery & routing',
    auth: 'Authentication',
    content: 'Format & content',
    list: 'Mailing lists & bulk mail',
    client: 'Sending software',
    spam: 'Spam & virus filtering',
    other: 'Other headers',
};

export interface HeaderInfo {
    title: string;
    category: Category;
    description: string;
    /** RFC or documentation that defines it. */
    spec?: string;
}

const h = (title: string, category: Category, description: string, spec?: string): HeaderInfo => ({ title, category, description, spec });

export const HEADERS: Record<string, HeaderInfo> = {
    // ------------------------------------------------ Sender & recipients
    from: h('From', 'identity', 'Who the message says it is from. Anyone can write anything here; DMARC is what ties it to the real sender.', 'RFC 5322'),
    sender: h('Sender', 'identity', 'The mailbox that actually sent the message, when different from From (e.g. an assistant sending on behalf of someone).', 'RFC 5322'),
    'reply-to': h('Reply-To', 'identity', 'Where replies go instead of the From address.', 'RFC 5322'),
    to: h('To', 'identity', 'The primary recipients, as written by the sender. Not necessarily who received it: see Delivered-To and the Received "for" clauses.', 'RFC 5322'),
    cc: h('Cc', 'identity', 'Carbon-copy recipients, visible to everyone.', 'RFC 5322'),
    bcc: h('Bcc', 'identity', 'Blind-copy recipients. Normally removed before delivery; seeing it usually means you are looking at the sender\'s copy.', 'RFC 5322'),
    'delivered-to': h('Delivered-To', 'routing', 'The mailbox the receiving server actually delivered to (after aliases and forwarding).'),
    'x-original-to': h('X-Original-To', 'routing', 'The recipient address as given by the sending server, before alias expansion (Postfix).'),
    'envelope-to': h('Envelope-To', 'routing', 'The envelope recipient (RCPT TO), added by Exim on delivery.'),
    'x-envelope-to': h('X-Envelope-To', 'routing', 'The envelope recipient (RCPT TO).'),
    'x-envelope-from': h('X-Envelope-From', 'routing', 'The envelope sender (MAIL FROM).'),
    'x-rcpt-to': h('X-Rcpt-To', 'routing', 'The envelope recipient (RCPT TO).'),
    'x-delivered-to': h('X-Delivered-To', 'routing', 'The mailbox the message was delivered to.'),
    'x-forwarded-to': h('X-Forwarded-To', 'routing', 'The address this message was automatically forwarded to.'),
    'x-forwarded-for': h('X-Forwarded-For', 'routing', 'Addresses the message was forwarded for, or (on webmail) the client IP behind a proxy.'),
    'x-original-sender': h('X-Original-Sender', 'identity', 'The original sender before a mailing list or group rewrote the message (Google Groups).'),
    'x-original-from': h('X-Original-From', 'identity', 'The From address before a list or forwarder rewrote it.'),
    'x-google-original-from': h('X-Google-Original-From', 'identity', 'The From address before Google Groups rewrote it.'),
    'dmarc-filter': h('DMARC-Filter', 'auth', 'Stamp left by the OpenDMARC filter on the receiving server: its version, the server and the queue id it checked.'),
    'dkim-filter': h('DKIM-Filter', 'auth', 'Stamp left by the OpenDKIM filter on the server that signed or checked the message: its version, the server and the queue id.'),
    comment: h('Comment', 'other', 'A free-text comment added by mail software (non-standard).'),
    'original-envelope-id': h('Original-Envelope-Id', 'routing', 'The id the sending server gave this message for delivery-status notifications, so bounces can be matched to it.', 'RFC 3461'),
    'x-jid': h('X-JID', 'other', "Zoho's job id for this message (ZeptoMail / Zoho apps)."),
    'tm-mail-jid': h('TM-MAIL-JID', 'other', "Zoho's transactional mail job id (ZeptoMail)."),
    'x-app-message-id': h('X-App-Message-ID', 'other', 'The id the sending application gave this message (Zoho).'),
    'x-zoho-cm-accountid': h('X-Zoho-CM-AccountID', 'other', 'Zoho\'s id for the customer account that sent this. Quote it when reporting abuse to Zoho.'),
    'x-zohomailclient': h('X-ZohoMailClient', 'other', 'How the message entered Zoho: "External" means from outside Zoho\'s own mail apps.'),
    'x-eventbrite': h('X-Eventbrite', 'other', 'Eventbrite\'s internal message ids (service, account, message).'),
    'x-eventbritemailer': h('X-EventbriteMailer', 'other', 'Which Eventbrite mail service generated the message.'),
    'x-msys-api': h('X-MSYS-API', 'other', 'Metadata the sender attached in the SparkPost (formerly Message Systems) API: campaign and tracking fields.'),
    'x-virtualservergroup': h('X-VirtualServerGroup', 'other', 'The pool of sending servers (Momentum/SparkPost) used for this message.'),
    'x-clientproxiedby': h('X-ClientProxiedBy', 'routing', "Exchange Online: the front-end server that relayed the sender's mail app to their mailbox server."),
    'x-ms-publictraffictype': h('X-MS-PublicTrafficType', 'routing', 'Exchange Online: the kind of traffic (Email for normal mail).'),
    'x-ms-traffictypediagnostic': h('X-MS-TrafficTypeDiagnostic', 'routing', 'Exchange Online: the servers that handled the message and in what role.'),
    'x-ms-exchange-senderadcheck': h('X-MS-Exchange-SenderADCheck', 'routing', "Exchange Online: whether the sender was looked up in the organisation's directory (1 = yes)."),
    'x-ms-exchange-antispam-relay': h('X-MS-Exchange-AntiSpam-Relay', 'spam', 'Exchange Online: anti-spam relay flag (0 = the message was not relayed by an anti-spam service).'),
    'x-ms-exchange-antispam-messagedata-chunkcount': h('X-MS-Exchange-AntiSpam-MessageData-ChunkCount', 'spam', 'Exchange Online: how many MessageData chunks follow.'),
    'x-originatororg': h('X-OriginatorOrg', 'identity', 'Exchange Online: the Microsoft 365 organisation (tenant) the message was sent from.'),
    'x-ms-exchange-transport-crosstenantheadersstamped': h('X-MS-Exchange-Transport-CrossTenantHeadersStamped', 'routing', 'Exchange Online: the server that added the cross-tenant headers as the message left the sending organisation.'),
    'x-spam-virus-scanned': h('X-SPAM-VIRUS-Scanned', 'spam', 'Which spam/virus scanner checked the message.'),
    'return-receipt-to': h('Return-Receipt-To', 'message', 'Old-style read/delivery receipt request.'),
    'delivery-date': h('Delivery-date', 'routing', 'When the final server (Exim) delivered the message to the mailbox.'),
    'x-originalarrivaltime': h('X-OriginalArrivalTime', 'routing', 'Exchange / IIS: when the message first arrived at a Microsoft mail server, in UTC and as a Windows FILETIME.'),
    'x-xerox-mail-id': h('X-Xerox-Mail-Id', 'client', "A Xerox printer/scanner's id for this scan-to-email message."),
    'x-proto': h('X-Proto', 'routing', 'The protocol the sending server used, as recorded by a filtering gateway.'),
    'x-revdns': h('X-Revdns', 'routing', "The sending server's reverse DNS name, as recorded by a filtering gateway."),
    'x-helo': h('X-HELO', 'routing', 'The name the sending server introduced itself with (HELO/EHLO), as recorded by a filtering gateway.'),
    'x-tls': h('X-TLS', 'routing', 'The TLS version/cipher of the incoming connection, as recorded by a filtering gateway. Empty means none.'),
    'x-authenticated_id': h('X-Authenticated_ID', 'routing', 'The account the sender logged in with, if any. Empty means none.'),
    'x-origin-ip': h('X-Origin-IP', 'routing', 'The IP address of the server that connected to the filtering gateway.'),
    'x-env-from': h('X-Env-From', 'routing', 'The envelope sender (MAIL FROM) seen by a filtering gateway.'),
    'x-dkim': h('X-DKIM', 'auth', "A filtering gateway's DKIM result."),
    'x-fm-os': h('X-FM-OS', 'routing', "electric.net's guess at the sending server's operating system, from how its network connection behaves (passive OS fingerprinting)."),
    'x-fm-geoip': h('X-FM-GeoIP', 'routing', "electric.net's country lookup for the sending server's IP."),
    'x-policysmart': h('X-PolicySMART', 'spam', 'electric.net PolicySMART: the id of the filtering policy applied.'),
    'return-path': h('Return-Path', 'routing', 'The envelope sender (MAIL FROM): where bounces go. Added by the final server on delivery; SPF checks this domain.', 'RFC 5321'),
    'errors-to': h('Errors-To', 'routing', 'Obsolete: where to send delivery errors. Return-Path is what servers actually use.'),
    'resent-from': h('Resent-From', 'identity', 'Who re-sent (redirected) this message.', 'RFC 5322'),
    'resent-to': h('Resent-To', 'identity', 'Who the message was re-sent to.', 'RFC 5322'),
    'resent-date': h('Resent-Date', 'message', 'When the message was re-sent.', 'RFC 5322'),
    'resent-message-id': h('Resent-Message-ID', 'message', 'Identifier of the re-sent copy.', 'RFC 5322'),
    'resent-sender': h('Resent-Sender', 'identity', 'The mailbox that re-sent the message.', 'RFC 5322'),

    // ------------------------------------------------------ Message
    subject: h('Subject', 'message', 'The subject line.', 'RFC 5322'),
    date: h('Date', 'message', "When the sender's software says the message was written. Set by the sender's own clock, so it can be wrong or faked; the Received timestamps are better evidence.", 'RFC 5322'),
    'message-id': h('Message-ID', 'message', "A unique identifier for this message, generated by the sender's software. Its domain often reveals the service or server that created it.", 'RFC 5322'),
    'in-reply-to': h('In-Reply-To', 'message', 'The Message-ID of the message this one replies to.', 'RFC 5322'),
    references: h('References', 'message', 'Message-IDs of earlier messages in the conversation, oldest first. Mail apps use it to build threads.', 'RFC 5322'),
    'thread-topic': h('Thread-Topic', 'message', 'Outlook/Exchange: the conversation topic (the subject without RE:/FW:).'),
    'thread-index': h('Thread-Index', 'message', 'Outlook/Exchange: a binary conversation index that encodes when the conversation started and how many replies deep this message is.'),
    importance: h('Importance', 'message', 'Priority flag set by the sender (high, normal, low).', 'RFC 2156'),
    priority: h('Priority', 'message', 'Priority (urgent, normal, non-urgent).', 'RFC 2156'),
    'x-priority': h('X-Priority', 'message', 'Priority flag: 1 = highest, 3 = normal, 5 = lowest. Spam often sets 1.'),
    'x-msmail-priority': h('X-MSMail-Priority', 'message', 'Outlook priority (High, Normal, Low).'),
    sensitivity: h('Sensitivity', 'message', 'Sensitivity flag: Personal, Private or Company-Confidential.', 'RFC 2156'),
    'disposition-notification-to': h('Disposition-Notification-To', 'message', 'The sender asked for a read receipt, to be sent to this address. Mail apps usually ask before sending one.', 'RFC 8098'),
    'x-confirm-reading-to': h('X-Confirm-Reading-To', 'message', 'Old-style read receipt request.'),
    organization: h('Organization', 'message', 'The organisation the sender belongs to, as they configured it.'),
    keywords: h('Keywords', 'message', 'Keywords or tags set by the sender.', 'RFC 5322'),
    comments: h('Comments', 'message', 'Free-text comments.', 'RFC 5322'),
    'content-language': h('Content-Language', 'content', 'Language(s) of the message text.', 'RFC 3282'),
    'accept-language': h('Accept-Language', 'content', 'Languages the sender\'s mail app is set to (Outlook).'),
    'x-ms-exchange-organization-messagedirectionality': h('Message direction', 'routing', 'Whether Exchange saw the message as Incoming (from outside) or Originating (from inside the organisation).'),

    // ------------------------------------------------------ Routing
    received: h('Received', 'routing', 'Added by each server that accepted the message, newest on top. Read bottom-up to follow its path. Only the ones added by servers you trust are reliable.', 'RFC 5321'),
    'x-received': h('X-Received', 'routing', "Google's internal hand-offs between its own servers, written like a Received header."),
    'x-originating-ip': h('X-Originating-IP', 'routing', "The IP address of the sender's own device or network, recorded by the webmail or submission server."),
    'x-sender-ip': h('X-Sender-IP', 'routing', 'The IP address that submitted the message.'),
    'x-client-ip': h('X-Client-IP', 'routing', 'The IP address of the client that submitted the message.'),
    'x-real-ip': h('X-Real-IP', 'routing', 'The IP address of the client behind a proxy.'),
    'x-ms-exchange-organization-originalclientipaddress': h('Original client IP', 'routing', 'The IP address of the client that connected to Exchange.'),
    'x-ms-exchange-organization-originalserveripaddress': h('Original server IP', 'routing', 'The IP address of the Exchange server that accepted the connection.'),

    // ------------------------------------------------ Authentication
    'authentication-results': h('Authentication-Results', 'auth', "A receiving server's verdicts on SPF, DKIM and DMARC. Only trust the ones your own provider added (normally the topmost).", 'RFC 8601'),
    'x-original-authentication-results': h('X-Original-Authentication-Results', 'auth', "Authentication results from an earlier server, kept when a gateway re-checks the message."),
    'received-spf': h('Received-SPF', 'auth', "The SPF check: is the connecting server's IP allowed to send for the envelope sender's domain?", 'RFC 7208'),
    'dkim-signature': h('DKIM-Signature', 'auth', 'A cryptographic signature over the body and selected headers, made with a key published in DNS by the signing domain (d=).', 'RFC 6376'),
    'domainkey-signature': h('DomainKey-Signature', 'auth', 'The pre-DKIM DomainKeys signature (obsolete since 2007).', 'RFC 4870'),
    'x-google-dkim-signature': h('X-Google-DKIM-Signature', 'auth', 'A DKIM signature Google adds for its own use (not checked by other receivers).'),
    'arc-seal': h('ARC-Seal', 'auth', "Part of ARC: seals the chain of authentication results so a forwarder or mailing list can vouch that the message passed checks before it was modified. cv= is the chain's validity when this hop added it.", 'RFC 8617'),
    'arc-message-signature': h('ARC-Message-Signature', 'auth', 'Part of ARC: a DKIM-like signature over the message as this forwarder received it.', 'RFC 8617'),
    'arc-authentication-results': h('ARC-Authentication-Results', 'auth', 'Part of ARC: the authentication results this forwarder saw, preserved for later receivers.', 'RFC 8617'),
    'bimi-selector': h('BIMI-Selector', 'auth', 'Which BIMI record (brand logo) the sender wants used.', 'BIMI draft'),
    'bimi-location': h('BIMI-Location', 'auth', "Added by the receiver: where the sender's verified brand logo is.", 'BIMI draft'),
    'bimi-indicator': h('BIMI-Indicator', 'auth', "Added by the receiver: the sender's brand logo (SVG, base64).", 'BIMI draft'),
    'tls-required': h('TLS-Required', 'auth', '"No" asks servers to deliver even if a secure (TLS) connection isn\'t possible, overriding MTA-STS/DANE.', 'RFC 8689'),
    'require-recipient-valid-since': h('Require-Recipient-Valid-Since', 'auth', 'Asks the receiver not to deliver if the mailbox changed owner after this date.', 'RFC 7293'),

    // -------------------------------------------------------- Content
    'mime-version': h('MIME-Version', 'content', 'Declares the message uses MIME (attachments, character sets, HTML). Always 1.0.', 'RFC 2045'),
    'content-type': h('Content-Type', 'content', 'What kind of content the body is (plain text, HTML, several alternatives, attachments) and its character set.', 'RFC 2045'),
    'content-transfer-encoding': h('Content-Transfer-Encoding', 'content', 'How the body is encoded to travel as plain text: 7bit/8bit (as is), quoted-printable or base64.', 'RFC 2045'),
    'content-disposition': h('Content-Disposition', 'content', 'Whether a part is shown inline or offered as an attachment, and its file name.', 'RFC 2183'),
    'content-id': h('Content-ID', 'content', 'Identifier used to refer to this part, e.g. an image embedded in the HTML.', 'RFC 2045'),
    'content-description': h('Content-Description', 'content', 'A description of the content.', 'RFC 2045'),
    'content-class': h('Content-Class', 'content', 'Exchange: the kind of item (e.g. urn:content-classes:message, a calendar item).'),
    'x-forefront-antispam-report': h('X-Forefront-Antispam-Report', 'spam', 'Microsoft 365: information about the message and how anti-spam filtering processed it. Fields not described by Microsoft are used only by its anti-spam team for diagnostics.', 'Microsoft: Anti-spam message headers'),
    'x-microsoft-antispam': h('X-Microsoft-Antispam', 'spam', 'Microsoft 365: additional information about bulk mail and phishing. Only BCL is documented; other fields are for Microsoft diagnostics.', 'Microsoft: Anti-spam message headers'),
    'x-ms-exchange-externaloriginalinternetsender': h('X-MS-Exchange-ExternalOriginalInternetSender', 'routing', "Microsoft 365 Enhanced Filtering for Connectors: the server that really sent the message, before it passed through another gateway (Mimecast, Proofpoint…) on its way to Microsoft 365."),
    'x-ms-exchange-skiplistedinternetsender': h('X-MS-Exchange-SkipListedInternetSender', 'routing', 'Microsoft 365 Enhanced Filtering for Connectors: gateway servers it skipped over to find the original sender.'),
    'x-ms-exchange-organization-bypassfocusedinbox': h('X-MS-Exchange-Organization-BypassFocusedInbox', 'routing', 'Exchange: whether an admin rule exempts the message from Focused Inbox sorting.'),
    'x-ms-exchange-enablefirstcontactsafetytip': h('X-MS-Exchange-EnableFirstContactSafetyTip', 'spam', "Exchange: set by a custom mail flow rule to show the \"You don't often get email from…\" safety tip."),
    'x-vr-spamcause': h('X-VR-SPAMCAUSE', 'spam', "OVH's spam filter: the reasons for its verdict, scrambled."),
    'x-customspam': h('X-CustomSpam', 'spam', "Microsoft 365: the message matched an Advanced Spam Filter (ASF) setting in the recipient organisation's anti-spam policy. Added after mail flow rules run, so rules can't act on it.", 'Microsoft: Anti-spam message headers'),
    'x-ms-has-attach': h('X-MS-Has-Attach', 'content', 'Outlook/Exchange: "yes" if the message has attachments.'),
    'x-ms-tnef-correlator': h('X-MS-TNEF-Correlator', 'content', 'Outlook/Exchange: links Outlook-specific (TNEF, winmail.dat) properties to this message.'),

    // ------------------------------------------------- Lists & bulk
    'list-unsubscribe': h('List-Unsubscribe', 'list', 'How to unsubscribe (a mailto: address and/or web link). Mail apps show an "Unsubscribe" button from it. Bulk senders to Gmail and Yahoo must include it.', 'RFC 2369'),
    'list-unsubscribe-post': h('List-Unsubscribe-Post', 'list', '"List-Unsubscribe=One-Click" means the web link unsubscribes with a single POST, no confirmation page.', 'RFC 8058'),
    'list-id': h('List-Id', 'list', 'Identifies the mailing list, for filtering.', 'RFC 2919'),
    'list-post': h('List-Post', 'list', 'How to post to the list.', 'RFC 2369'),
    'list-help': h('List-Help', 'list', 'Where to get help with the list.', 'RFC 2369'),
    'list-subscribe': h('List-Subscribe', 'list', 'How to subscribe to the list.', 'RFC 2369'),
    'list-owner': h('List-Owner', 'list', 'How to contact the list owner.', 'RFC 2369'),
    'list-archive': h('List-Archive', 'list', "The list's archive.", 'RFC 2369'),
    precedence: h('Precedence', 'list', 'bulk, list or junk: tells auto-responders (out-of-office replies) not to answer.'),
    'auto-submitted': h('Auto-Submitted', 'list', 'Marks machine-generated mail (auto-generated, auto-replied) so other robots don\'t reply to it.', 'RFC 3834'),
    'x-auto-response-suppress': h('X-Auto-Response-Suppress', 'list', 'Exchange: which automatic replies (out-of-office, read receipts…) should not be sent in response.'),
    'feedback-id': h('Feedback-ID', 'list', "Identifiers for Gmail's feedback loop. When Gmail users mark mail as spam, Gmail tells the sending service (last part) which of these campaigns or customers drew the complaints, as statistics in Google Postmaster Tools. There's no address to send reports to: marking the message as spam in Gmail is what feeds it. To report the sender, use the contacts under Where to report it on the Summary.", 'Gmail FBL'),
    'x-csa-complaints': h('X-CSA-Complaints', 'list', 'The sender is certified by the Certified Senders Alliance; complaints go to this address.'),
    'x-report-abuse': h('X-Report-Abuse', 'list', 'Where to report this message as abuse.'),
    'x-complaints-to': h('X-Complaints-To', 'list', 'Where to send abuse complaints.'),
    'x-abuse-info': h('X-Abuse-Info', 'list', 'How to report abuse.'),
    'x-mailer-recptid': h('X-Mailer-RecptId', 'list', 'Recipient identifier used by the sending platform for tracking.'),
    'x-campaign': h('X-Campaign', 'list', 'Campaign identifier set by the sending platform.'),
    'x-campaignid': h('X-CampaignID', 'list', 'Campaign identifier set by the sending platform.'),
    'x-mc-user': h('X-MC-User', 'list', 'Mailchimp account identifier.'),
    'x-mailer-lid': h('X-Mailer-LID', 'list', 'Mailchimp list (audience) identifiers.'),
    'x-accounttype': h('X-Accounttype', 'list', 'Mailchimp account plan type.'),

    // --------------------------------------------------------- Client
    'x-mailer': h('X-Mailer', 'client', 'The program or service that composed the message.'),
    'user-agent': h('User-Agent', 'client', 'The mail app that composed the message.'),
    'x-mimeole': h('X-MimeOLE', 'client', 'The Microsoft MIME library version (old Outlook/Exchange).'),
    'x-generator': h('X-Generator', 'client', 'The software that generated the message.'),
    'x-originating-client': h('X-Originating-Client', 'client', 'Exchange: the client used to send (e.g. Outlook on the web).'),
    'x-php-originating-script': h('X-PHP-Originating-Script', 'client', 'A PHP script on a web server sent this message: user id and file name.'),
    'x-php-script': h('X-PHP-Script', 'client', 'A PHP script on a web server sent this message.'),

    // ----------------------------------------------------------- Spam
    'x-spam-status': h('X-Spam-Status', 'spam', 'SpamAssassin\'s verdict: Yes/No, the score and the threshold, and the rules that matched.'),
    'x-spam-score': h('X-Spam-Score', 'spam', 'Spam score from the filter; higher is spammier.'),
    'x-spam-level': h('X-Spam-Level', 'spam', 'The spam score drawn as a row of asterisks (one per point), for easy filtering.'),
    'x-spam-flag': h('X-Spam-Flag', 'spam', 'YES when the filter considered it spam.'),
    'x-spam-checker-version': h('X-Spam-Checker-Version', 'spam', 'Which SpamAssassin version and server checked it.'),
    'x-spam-test-scores': h('X-Spam-Test-Scores', 'spam', 'Each SpamAssassin rule that matched and the points it added (negative points make it look less like spam).'),
    'x-spam-last-external-ip': h('X-Spam-Last-External-IP', 'spam', 'The address of the last server outside your provider, as SpamAssassin determined it.'),
    'x-spam-last-external-helo': h('X-Spam-Last-External-HELO', 'spam', 'The HELO name of the last outside server.'),
    'x-spam-last-external-rdns': h('X-Spam-Last-External-rDNS', 'spam', 'The reverse DNS name of the last outside server.'),
    'x-spam-date-of-scan': h('X-Spam-Date-of-Scan', 'spam', 'When SpamAssassin scanned the message.'),
    'x-spam-report': h('X-Spam-Report', 'spam', 'Detailed SpamAssassin report: each rule that matched and its points.'),
    'x-spam-bar': h('X-Spam-Bar', 'spam', 'The spam score drawn as a bar (+ or -).'),
    'x-virus-scanned': h('X-Virus-Scanned', 'spam', 'Which virus scanner checked the message.'),
    'x-virus-status': h('X-Virus-Status', 'spam', 'The virus scanner\'s verdict.'),
    'x-spamd-result': h('X-Spamd-Result', 'spam', "Rspamd's verdict: the score, the threshold and every symbol (rule) that matched."),
    'x-spamd-bar': h('X-Spamd-Bar', 'spam', "Rspamd's score drawn as a bar."),
    'x-rspamd-score': h('X-Rspamd-Score', 'spam', "Rspamd's spam score."),
    'x-rspamd-action': h('X-Rspamd-Action', 'spam', 'What Rspamd decided to do: no action, greylist, add header, rewrite subject, reject.'),
    'x-rspamd-server': h('X-Rspamd-Server', 'spam', 'The Rspamd server that scanned the message.'),
    'x-rspamd-queue-id': h('X-Rspamd-Queue-Id', 'spam', "The mail server's queue id for the message, as seen by Rspamd."),
};

/** Families of headers described by pattern. First match wins. */
export const HEADER_PATTERNS: [RegExp, HeaderInfo][] = [
    [/^arc-/, h('ARC', 'auth', 'Authenticated Received Chain: lets forwarders vouch for authentication results.', 'RFC 8617')],
    [/^list-/, h('Mailing list', 'list', 'Mailing list metadata.', 'RFC 2369')],
    [/^content-/, h('MIME', 'content', 'Describes the message content.', 'RFC 2045')],
    [/^resent-/, h('Resent', 'identity', 'Added when the message was re-sent (redirected) by someone.', 'RFC 5322')],
    [/^x-ms-exchange-antispam-messagedata-\d+$/, h('Exchange anti-spam data', 'spam', "Exchange Online: encoded anti-spam data passed between Microsoft's servers. It can't be read outside Microsoft.")],
    [/^x-ms-exchange-crosstenant-/, h('Exchange cross-tenant', 'routing', 'Exchange Online: information carried between organisations (tenants), such as when the message first arrived and whether the sender was internal.')],
    [/^x-ms-exchange-/, h('Exchange', 'routing', 'Microsoft Exchange internal processing information.')],
    [/^x-microsoft-antispam/, h('Microsoft anti-spam', 'spam', 'Exchange Online Protection anti-spam details.')],
    [/^x-forefront-/, h('Microsoft anti-spam', 'spam', 'Exchange Online Protection anti-spam details.')],
    [/^x-ms-/, h('Microsoft', 'other', 'Microsoft Exchange / Outlook processing information.')],
    [/^x-ses-/, h('Amazon SES', 'other', 'Added by Amazon SES.')],
    [/^x-gm-|^x-google-/, h('Google', 'other', "Google's own processing information (opaque, often encrypted).")],
    [/^x-spam-/, h('Spam filter', 'spam', 'Spam filter information.')],
    [/^x-virus-/, h('Virus scan', 'spam', 'Virus scanner information.')],
    [/^x-rspamd-|^x-spamd-/, h('Rspamd', 'spam', 'Rspamd spam filter information.')],
    [/^x-proofpoint-/, h('Proofpoint', 'spam', 'Proofpoint email security processing details.')],
    [/^x-mimecast-/, h('Mimecast', 'spam', 'Mimecast email security processing details.')],
    [/^x-barracuda-|^x-asg-/, h('Barracuda', 'spam', 'Barracuda email security processing details.')],
    [/^x-ironport-/, h('Cisco IronPort', 'spam', 'Cisco Secure Email processing details.')],
    [/^x-/, h('Custom header', 'other', 'A non-standard header ("X-" prefix) added by some software along the way.')],
];

export function headerInfo(key: string): HeaderInfo | null {
    return HEADERS[key] ?? HEADER_PATTERNS.find(([pattern]) => pattern.test(key))?.[1] ?? null;
}
