/**
 * Mail services the analyzer recognises, and the traces each one leaves:
 *
 * - headers:    names of the headers it adds (lower case)
 * - hosts:      host-name suffixes of its servers, as seen in Received headers
 * - messageIds: Message-ID domain suffixes it generates
 * - dkim:       domains it signs with (DKIM d=)
 * - feedbackId: the last field of its Feedback-ID header (Gmail feedback loop)
 * - abuse:      where to report spam/phishing sent through it
 * - account:    headers whose values identify the customer account; quote them in a report
 *
 * A service's headers are grouped under its name on the Headers tab. Order
 * matters only where two services share a header prefix (Postmark and Proton
 * both use X-PM-): the one with more other evidence wins.
 */
export interface Service {
    name: string;
    kind: string;
    about: string;
    url?: string;
    headers?: RegExp;
    hosts?: string[];
    messageIds?: string[];
    dkim?: string[];
    feedbackId?: RegExp;
    /** Generic-looking headers grouped under this service only once other evidence finds it. */
    relatedHeaders?: RegExp;
    abuse?: { email?: string; url?: string };
    account?: string[];
}

/** Kinds whose own headers are written when the message is sent (so they're on the sender's side). */
export const SENDING_KINDS = new Set(['Email sending service', 'Marketing platform', 'Help desk']);

export const SERVICES: Service[] = [
    // ------------------------------------------------ Sending services
    {
        name: 'Amazon SES',
        kind: 'Email sending service',
        about: "Amazon Simple Email Service: AWS's bulk and transactional email API. The sender's own domain is usually layered on top, so look at the headers below for the AWS region and when SES sent it.",
        url: 'https://aws.amazon.com/ses/',
        headers: /^(x-ses-|x-amz-)/,
        hosts: ['amazonses.com', 'smtp-out.amazonses.com'],
        messageIds: ['amazonses.com'],
        dkim: ['amazonses.com'],
        feedbackId: /^AmazonSES$/i,
        abuse: { email: 'email-abuse@amazon.com', url: 'https://support.aws.amazon.com/#/contacts/report-abuse' },
        account: ['feedback-id', 'x-ses-configuration-set', 'message-id'],
    },
    {
        name: 'SendGrid',
        kind: 'Email sending service',
        about: "Twilio SendGrid, a transactional and marketing email API. X-SG-EID and X-SG-ID are SendGrid's encrypted message and recipient identifiers.",
        url: 'https://sendgrid.com/',
        headers: /^(x-sg-|x-entity-id$)/,
        hosts: ['sendgrid.net', 'sendgrid.com'],
        messageIds: ['sendgrid.net', 'geopod-ismtpd'],
        dkim: ['sendgrid.info', 'sendgrid.net'],
        abuse: { email: 'abuse@sendgrid.com' },
        account: ['x-sg-eid', 'x-sg-id', 'x-entity-id'],
    },
    {
        name: 'Mailgun',
        kind: 'Email sending service',
        about: 'Mailgun (Sinch), a transactional email API.',
        url: 'https://www.mailgun.com/',
        headers: /^x-mailgun-/,
        hosts: ['mailgun.net', 'mailgun.org', 'mailgun.info', 'mg.mailgun.net'],
        dkim: ['mailgun.org', 'mailgun.net'],
        abuse: { email: 'abuse@mailgun.com' },
        account: ['x-mailgun-sid', 'x-mailgun-tag'],
    },
    {
        name: 'Postmark',
        kind: 'Email sending service',
        about: 'Postmark (ActiveCampaign), a transactional email API.',
        url: 'https://postmarkapp.com/',
        headers: /^x-pm-(message-id|tag|rcpt|metadata-)/,
        hosts: ['mtasv.net', 'postmarkapp.com'],
        messageIds: ['mtasv.net'],
        dkim: ['pm.mtasv.net', 'postmarkapp.com'],
        abuse: { email: 'abuse@postmarkapp.com' },
        account: ['x-pm-message-id', 'x-pm-tag'],
    },
    {
        name: 'SparkPost',
        kind: 'Email sending service',
        about: 'SparkPost (Bird), an email delivery API. X-MSFBL carries an encoded feedback-loop identifier.',
        headers: /^(x-msfbl|x-msys-api)$/,
        hosts: ['sparkpostmail.com', 'sparkpostmail1.com', 'e.sparkpost.com'],
        relatedHeaders: /^x-virtualservergroup$/,
        dkim: ['sparkpostmail.com'],
        abuse: { email: 'abuse@sparkpost.com' },
        account: ['x-msfbl'],
    },
    {
        name: 'Mailchimp',
        kind: 'Marketing platform',
        about: 'Mailchimp (Intuit) newsletters and marketing email.',
        url: 'https://mailchimp.com/',
        headers: /^(x-mc-user$|x-mailer-lid$|x-mailchimp-|x-accounttype$|x-mc-ip$)/,
        // Generic names other senders use too: grouped here only once Mailchimp is found another way.
        relatedHeaders: /^x-campaignid$/,
        hosts: ['mcsv.net', 'rsgsv.net', 'mcdlv.net', 'mailchimpapp.net', 'mailchimp.com'],
        dkim: ['mcsv.net', 'mailchimpapp.net', 'mcdlv.net'],
        abuse: { email: 'abuse@mailchimp.com', url: 'https://mailchimp.com/contact/abuse/' },
        account: ['x-mc-user', 'x-campaignid', 'list-id'],
    },
    {
        name: 'Mailchimp Transactional (Mandrill)',
        kind: 'Email sending service',
        about: "Mandrill, Mailchimp's transactional email API.",
        headers: /^x-mandrill-|^x-mc-(metadata|tags|track|subaccount)/,
        hosts: ['mandrillapp.com'],
        messageIds: ['mandrillapp.com'],
        dkim: ['mandrillapp.com'],
        abuse: { url: 'https://mailchimp.com/contact/abuse/' },
        account: ['x-mandrill-user', 'x-mc-user'],
    },
    {
        name: 'Brevo (Sendinblue)',
        kind: 'Email sending service',
        about: 'Brevo, formerly Sendinblue: marketing and transactional email.',
        headers: /^(x-mailin-|x-sib-|x-sib)/,
        hosts: ['sendinblue.com', 'brevo.com', 'sender-sib.com', 'smtp-relay.sendinblue.com'],
        dkim: ['sendinblue.com', 'brevo.com', 'sender-sib.com'],
        abuse: { email: 'abuse@brevo.com' },
        account: ['x-mailin-eid', 'x-sib-id', 'x-mailin-client'],
    },
    {
        name: 'Mailjet',
        kind: 'Email sending service',
        about: 'Mailjet (Sinch), marketing and transactional email.',
        headers: /^(x-mj-|x-mailjet-)/,
        hosts: ['mailjet.com', 'mjrelay.com'],
        dkim: ['mailjet.com'],
        abuse: { email: 'abuse@mailjet.com' },
        account: ['x-mj-mid', 'x-mailjet-campaign'],
    },
    {
        name: 'Constant Contact',
        kind: 'Marketing platform',
        about: 'Constant Contact email marketing. X-Roving-ID identifies the account and campaign.',
        headers: /^x-roving-/,
        hosts: ['ccsend.com', 'constantcontact.com', 'ctctcdn.com'],
        dkim: ['ccsend.com', 'auth.ccsend.com'],
        abuse: { email: 'abuse@constantcontact.com' },
        account: ['x-roving-id', 'x-roving-campaignid'],
    },
    {
        name: 'HubSpot',
        kind: 'Marketing platform',
        about: 'HubSpot marketing and sales email.',
        headers: /^x-hs-/,
        hosts: ['hubspotemail.net', 'hubspot.com', 'hubspotstarter.net'],
        dkim: ['hubspotemail.net', 'hubspotstarter.net'],
        abuse: { email: 'abuse@hubspot.com' },
        account: ['x-hs-cid'],
    },
    {
        name: 'Salesforce',
        kind: 'Marketing platform',
        about: 'Salesforce (including Marketing Cloud / ExactTarget).',
        headers: /^(x-sfdc-|x-sfmc-|x-mail_abuse_inquiries)/,
        hosts: ['salesforce.com', 'exacttarget.com', 'sfmc-mail.com', 'mc.salesforce.com'],
        dkim: ['salesforce.com', 'exacttarget.com'],
        abuse: { email: 'abuse@salesforce.com' },
        account: ['x-sfdc-lk', 'x-sfdc-user'],
    },
    {
        name: 'Klaviyo',
        kind: 'Marketing platform',
        about: 'Klaviyo e-commerce marketing email.',
        headers: /^x-kmail-|^x-klaviyo-/,
        hosts: ['klaviyomail.com', 'klaviyo.com'],
        dkim: ['klaviyomail.com', 'klaviyo.com'],
        abuse: { email: 'abuse@klaviyo.com' },
    },
    {
        name: 'Eventbrite',
        kind: 'Marketing platform',
        about: 'Eventbrite event invitations and ticket mail (often sent through SparkPost).',
        headers: /^x-eventbrite/,
        hosts: ['eventbrite.com', 'eventbritemail.com'],
        dkim: ['eventbrite.com', 'eventbritemail.com'],
        account: ['x-eventbrite'],
    },
    {
        name: 'Zendesk',
        kind: 'Help desk',
        about: 'Zendesk support tickets.',
        headers: /^x-zendesk-/,
        hosts: ['zendesk.com'],
        dkim: ['zendesk.com'],
        abuse: { email: 'abuse@zendesk.com' },
    },
    {
        name: 'Freshdesk',
        kind: 'Help desk',
        about: 'Freshworks Freshdesk support tickets.',
        headers: /^x-fd-|^x-freshdesk-/,
        hosts: ['freshdesk.com', 'freshemail.io'],
    },

    // ----------------------------------------------- Mailbox providers
    {
        name: 'Microsoft (Exchange / Outlook)',
        kind: 'Mailbox provider',
        about: 'Exchange Online (Microsoft 365, Outlook.com), an Exchange server, or the Outlook app. Exchange records its spam verdict, the connecting IP and country, and the organisation (tenant) the mail was for.',
        headers: /^(x-ms-|x-microsoft-|x-forefront-|x-originatororg$|x-originalarrivaltime$|x-clientproxiedby$|x-eopattributedmessage$|x-eoptenantattributedmessage$|x-exchange-|x-mimeole$|thread-index$|thread-topic$|x-auto-response-suppress$|x-mailer-msexchange)/,
        hosts: ['outlook.com', 'office365.com', 'protection.outlook.com', 'outbound.protection.outlook.com', 'hotmail.com', 'microsoft.com'],
        messageIds: ['prod.outlook.com', 'outlook.com', 'hotmail.com'],
        dkim: ['onmicrosoft.com', 'outlook.com', 'hotmail.com'],
        abuse: { url: 'https://msrc.microsoft.com/report/abuse' },
        account: ['x-originating-email', 'x-ms-exchange-crosstenant-id'],
    },
    {
        name: 'Google (Gmail / Workspace)',
        kind: 'Mailbox provider',
        about: "Gmail or Google Workspace. Google's own headers (X-Gm-*, X-Google-*) are opaque and encrypted; they mostly matter to Google.",
        headers: /^(x-gm-|x-google-|x-received$|x-gmail-)/,
        hosts: ['google.com', 'googlemail.com', 'gmail.com', 'gmr-mx.google.com'],
        messageIds: ['mail.gmail.com', 'google.com'],
        dkim: ['gmail.com', 'google.com', 'googlegroups.com', '1e100.net', 'gappssmtp.com'],
        abuse: { url: 'https://support.google.com/mail/contact/abuse' },
    },
    {
        name: 'Yahoo / AOL',
        kind: 'Mailbox provider',
        about: 'Yahoo Mail or AOL Mail (both run by Yahoo).',
        headers: /^(x-ymail-|x-yahoo-|x-sonic-|x-aol-|x-apparently-to$|x-ymailisg$)/,
        hosts: ['yahoo.com', 'yahoodns.net', 'aol.com', 'mail.yahoo.com'],
        messageIds: ['mail.yahoo.com', 'aol.com'],
        dkim: ['yahoo.com', 'aol.com'],
    },
    {
        name: 'Apple iCloud Mail',
        kind: 'Mailbox provider',
        about: 'iCloud Mail (icloud.com, me.com, mac.com).',
        headers: /^(x-apple-|x-icloud-|x-proofpoint-spam-details-enc$)/,
        hosts: ['icloud.com', 'me.com', 'mac.com', 'apple.com'],
        dkim: ['icloud.com', 'me.com', 'mac.com'],
        abuse: { email: 'abuse@icloud.com' },
    },
    {
        name: 'Zoho (Mail / ZeptoMail / Campaigns)',
        kind: 'Mailbox provider',
        about: 'Zoho Mail, ZeptoMail (Zoho\'s transactional sending service) or Zoho Campaigns. Zoho\'s support and app mailers send through ZeptoMail too.',
        headers: /^(x-zoho|x-jid$|tm-mail-jid$|x-app-message-id$)/,
        hosts: ['zoho.com', 'zohomail.com', 'zoho.eu', 'zoho.in', 'zeptomail.net', 'zeptomail.com', 'zeptomail.eu', 'zeptomail.in', 'zohosupport.com', 'zcsend.net', 'maillist-manage.com', 'maillist-manage.eu'],
        messageIds: ['zohosupport.com', 'zeptomail.net', 'zohomail.com'],
        dkim: ['zoho.com', 'zohomail.com', 'zeptomail.net', 'zohosupport.com'],
        feedbackId: /^Zoho/i,
        abuse: { email: 'abuse@zohocorp.com' },
        account: ['x-zoho-cm-accountid', 'x-jid'],
    },
    {
        name: 'Fastmail',
        kind: 'Mailbox provider',
        about: 'Fastmail (servers named messagingengine.com).',
        headers: /^x-me-/,
        hosts: ['messagingengine.com', 'fastmail.com'],
        dkim: ['messagingengine.com', 'fastmail.com'],
    },
    {
        name: 'Proton Mail',
        kind: 'Mailbox provider',
        about: 'Proton Mail. Its X-Pm-* headers say whether the message was end-to-end encrypted.',
        headers: /^x-pm-(origin|content-encryption|spamscore|spam-action|date|external-id|internal-id|recipient-|scheduled-sent|transfer-encryption|message-id)/,
        hosts: ['protonmail.ch', 'proton.me', 'protonmail.com'],
        dkim: ['protonmail.ch', 'proton.me', 'protonmail.com'],
        abuse: { email: 'abuse@proton.me' },
    },
    {
        name: 'GMX / Web.de / mail.com',
        kind: 'Mailbox provider',
        about: '1&1 Mail & Media (GMX, WEB.DE, mail.com).',
        headers: /^(x-ui-|x-provags-id$)/,
        hosts: ['gmx.net', 'gmx.com', 'web.de', 'mail.com', 'kundenserver.de'],
        dkim: ['gmx.net', 'gmx.com', 'web.de', 'mail.com'],
    },

    // ------------------------------------------- Security gateways
    {
        name: 'Proofpoint',
        kind: 'Security gateway',
        about: 'Proofpoint email security. It scans mail before it reaches the mailbox and records its spam and virus verdicts.',
        headers: /^x-proofpoint-/,
        hosts: ['pphosted.com', 'ppe-hosted.com', 'proofpoint.com'],
    },
    {
        name: 'Mimecast',
        kind: 'Security gateway',
        about: 'Mimecast email security gateway.',
        headers: /^x-mimecast-/,
        hosts: ['mimecast.com', 'mimecast-offshore.com', 'mimecast.co.za'],
    },
    {
        name: 'Barracuda',
        kind: 'Security gateway',
        about: 'Barracuda Email Security Gateway / Email Protection.',
        headers: /^(x-barracuda-|x-asg-)/,
        hosts: ['barracudanetworks.com', 'cudamail.com', 'ess.barracudanetworks.com'],
    },
    {
        name: 'Cisco Secure Email (IronPort)',
        kind: 'Security gateway',
        about: 'Cisco Secure Email Gateway, formerly IronPort.',
        headers: /^(x-ironport-|x-ipas-result$|x-ip-)/,
        hosts: ['iphmx.com'],
    },
    {
        name: 'Trend Micro',
        kind: 'Security gateway',
        about: 'Trend Micro Email Security.',
        headers: /^(x-tm-|x-tmase-|x-tmes-)/,
        hosts: ['tmes.trendmicro.com', 'tmes.trendmicro.eu'],
    },
    {
        name: 'Sophos',
        kind: 'Security gateway',
        about: 'Sophos Email.',
        headers: /^(x-sophos-|x-lasered$)/,
        hosts: ['sophos.com', 'prod.hydra.sophos.com'],
    },
    {
        name: 'Electric Mail Company (electric.net)',
        kind: 'Security gateway',
        about: 'A hosted mail filtering and relay service (SMARTsend / VirusSMART / PolicySMART). It records what it saw about the sending server: its reverse DNS, HELO name, protocol, TLS and even a guess at its operating system.',
        headers: /^(x-fm-|x-policysmart$)/,
        hosts: ['electric.net'],
        relatedHeaders: /^(x-proto|x-revdns|x-helo|x-tls|x-authenticated_id|x-origin-ip|x-env-from|x-dkim|x-virus-status)$/,
    },
    {
        name: 'SpamExperts / N-able',
        kind: 'Security gateway',
        about: 'SpamExperts (N-able Mail Assure, also sold by many web hosts).',
        headers: /^(x-spampanel-|x-recommended-action$|x-filter-id$|x-report-abuse-to$)/,
        hosts: ['antispamcloud.com', 'spamexperts.com', 'mailassure.n-able.com'],
    },

    // ------------------------------------------------- Spam filters
    {
        name: 'SpamAssassin',
        kind: 'Spam filter',
        about: 'Apache SpamAssassin scores each message by adding up points from rules (tests); at or above the threshold it is marked as spam.',
        headers: /^x-spam-/,
    },
    {
        name: 'Rspamd',
        kind: 'Spam filter',
        about: 'Rspamd spam filter: a score from weighted symbols and an action (no action, add header, reject…).',
        headers: /^(x-rspamd-|x-spamd-)/,
    },

    // ------------------------------------------- Hosting / servers
    {
        name: 'cPanel (Exim)',
        kind: 'Hosting control panel',
        about: 'A shared or reseller web host running cPanel, whose Exim mail server records which account sent the message.',
        headers: /^(x-antiabuse$|x-get-message-sender-via$|x-authenticated-sender$|x-source$|x-source-args$|x-source-dir$|x-from-rewrite$|x-source-l$|x-source-ip$|x-exim-id$|x-email-count$|x-org$|x-ctch-)/,
        account: ['x-get-message-sender-via', 'x-authenticated-sender', 'x-antiabuse', 'x-source-dir', 'x-source-args'],
    },
];

const byName = new Map(SERVICES.map((s) => [s.name, s]));

export function serviceNamed(name: string): Service | undefined {
    return byName.get(name);
}

/** "a11-162.smtp-out.amazonses.com" matches the suffix "amazonses.com". */
export function hostMatches(host: string | null | undefined, suffixes: string[] | undefined): boolean {
    if (!host || !suffixes) return false;
    const h = host.toLowerCase().replace(/\.$/, '');
    return suffixes.some((s) => h === s || h.endsWith(`.${s}`));
}
