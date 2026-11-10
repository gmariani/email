import { describe, expect, it } from 'vitest';
import m365 from '../../../tests/fixtures/m365.eml?raw';
import rfc8463 from '../../../tests/fixtures/rfc8463-ed25519.eml?raw';
import sesExim from '../../../tests/fixtures/ses-exim.eml?raw';
import spamwall from '../../../tests/fixtures/spamwall-sparkpost.eml?raw';
import { parseAddressList } from './address';
import { analyze } from './analyze';
import { organizationalDomain, parseAuthResults, sourceLabel, summarizeAuth } from './auth';
import { parseDate } from './date';
import { canonicalizeBody, canonicalizeHeader, verifyDkim } from './dkimVerify';
import { decodeEncodedWords, decodeQuotedPrintable } from './encoding';
import { sesTimestamp } from './explain/amazon';
import { decodeSpamcause } from './explain/spam';
import { decodeThreadIndex } from './explain/standard';
import { formatInZone, formatUtc } from './format';
import { NotAnEmailError, splitMessage } from './message';
import { leafParts, unwrapLink } from './mime';
import { msgToEml, type MsgSource } from './outlook';
import { htmlFromRtf } from './rtf';
import { parseReceived, securityOf } from './received';
import { buildRoute } from './route';
import { authConflicts, checkQuery, withLive, type LiveAuth } from './liveAuth';
import { checkText, decodeDomain, findLookalikes } from './lookalike';
import { networkTargets, originalSender, senderReport } from './sender';
import { buildStops, lookupTargets } from './stops';

const field = (name: string, value: string) => ({ index: 0, name, key: name.toLowerCase(), raw: `${name}: ${value}`, value, decoded: value });

describe('Received headers', () => {
    it("reads the user's Exim example", () => {
        const r = parseReceived(
            'from spamwall.example.org ([203.0.113.191]:17784) by mail.hosting.example.net with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (Exim 4.100.1) (envelope-from <0100@rsend.keymimestate.com>) id 1xKQbK-00000001LyQ-2KXG for recipient@example.org; Fri, 23 Oct 2026 21:31:12 -0400',
        );
        expect(r.from).toMatchObject({ name: 'spamwall.example.org', ip: '203.0.113.191', port: 17784 });
        expect(r.by?.name).toBe('mail.hosting.example.net');
        expect(r.protocol).toBe('esmtps');
        expect(r.tls).toMatchObject({ version: 'TLS 1.2', cipher: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' });
        expect(r.software).toBe('Exim 4.100.1');
        expect(r.envelopeFrom).toBe('0100@rsend.keymimestate.com');
        expect(r.id).toBe('1xKQbK-00000001LyQ-2KXG');
        expect(r.for).toBe('recipient@example.org');
        expect(formatUtc(r.date!.time)).toBe('2026-10-24 01:31:12 UTC');
        expect(formatInZone(r.date!.time, r.date!.offset)).toBe('Fri, 23 Oct 2026 21:31:12 -0400');
        expect(securityOf(r)).toBe('encrypted');
    });

    it('reads Postfix TLS comments and reverse DNS', () => {
        const r = parseReceived(
            'from a11-162.smtp-out.amazonses.com (a11-162.smtp-out.amazonses.com [54.240.11.162]) by spamwall.example.org (Postfix) with ESMTPS id 4cTQ1m0Xyz3kZ (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)) for <a@b.org>; Fri, 23 Oct 2026 21:31:10 -0400 (EDT)',
        );
        expect(r.from).toMatchObject({ rdns: 'a11-162.smtp-out.amazonses.com', ip: '54.240.11.162' });
        expect(r.software).toBe('Postfix');
        expect(r.tls).toMatchObject({ version: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', bits: '256/256' });
    });

    it('reads Microsoft and Sendmail styles', () => {
        const ms = parseReceived(
            'from mail-sor-f41.google.com (209.85.220.41) by DM6NAM12FT062.mail.protection.outlook.com (10.13.179.60) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8293.0 via Frontend Transport; Thu, 8 Jan 2026 15:22:39 +0000',
        );
        expect(ms.protocol).toBe('Microsoft SMTP Server');
        expect(ms.from?.ip).toBe('209.85.220.41');
        expect(ms.by?.ip).toBe('10.13.179.60');
        expect(ms.via).toBe('Frontend Transport');
        expect(ms.tls?.version).toBe('TLS 1.3');
        expect(ms.software).toBe('Microsoft Exchange');

        const sendmail = parseReceived('from host.example.net (host.example.net [198.51.100.7]) by mx.example.org (8.15.2/8.15.2) with ESMTP id 12ABCD (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO); Mon, 5 Jan 2026 10:00:00 GMT');
        expect(sendmail.software).toBe('Sendmail 8.15.2');
        expect(sendmail.tls).toMatchObject({ version: 'TLS 1.2', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', verify: 'NO' });
    });

    it('flags unencrypted, local and authenticated hops', () => {
        const plain = parseReceived('from mail.example.net (mail.example.net [198.51.100.7]) by mx.example.org with ESMTP id 1; Mon, 5 Jan 2026 10:00:00 +0000');
        expect(securityOf(plain)).toBe('unencrypted');
        const local = parseReceived('from localhost (localhost [127.0.0.1]) by mx.example.org (Postfix) with ESMTP id 2; Mon, 5 Jan 2026 10:00:00 +0000');
        expect(securityOf(local)).toBe('local');
        const auth = parseReceived('from [10.0.0.5] (Authenticated sender: jane@example.org) by smtp.example.org with ESMTPSA id 3; Mon, 5 Jan 2026 10:00:00 +0000');
        expect(auth.authenticated).toBe('jane@example.org');
        expect(auth.from?.ip).toBe('10.0.0.5');
    });

    it('reads the older Exim TLS notation and flags TLS 1.0', () => {
        const r = parseReceived(
            'from 198-51-100-253-static.hfc.comcastbusiness.net ([198.51.100.253]:36932 helo=XRX9C934E56C5A5.example.org) by host.hosting.example.net with esmtpsa (TLSv1:ECDHE-RSA-AES256-SHA:256) (Exim 4.89_1) (envelope-from <xerox@example.org>) id 1eX7lO-000FMv-T3; Thu, 04 Jan 2018 10:49:03 -0500',
        );
        expect(r.tls).toMatchObject({ version: 'TLS 1.0', cipher: 'ECDHE-RSA-AES256-SHA', bits: '256' });
        expect(r.from).toMatchObject({ helo: 'XRX9C934E56C5A5.example.org', port: 36932 });
        expect(r.software).toBe('Exim 4.89_1');
        const route = buildRoute(splitMessage('Received: from x.example.net ([198.51.100.253]) by mx.example.org with esmtpsa (TLSv1:ECDHE-RSA-AES256-SHA:256) id 1; Thu, 04 Jan 2018 10:49:03 -0500\n').headers);
        expect(route.hops[0].warnings[0]).toContain('TLS 1.0 is obsolete');
    });

    it('reads IIS pickup and SMTPSVC hops, and internal hand-offs', () => {
        const pickup = parseReceived('from mail pickup service by web1.corp.local with Microsoft SMTPSVC; Mon, 8 Jan 2018 16:02:46 -0600');
        expect(pickup).toMatchObject({ protocol: 'Microsoft SMTPSVC', software: 'Microsoft IIS SMTP' });
        expect(securityOf(pickup)).toBe('local');
        const iis = parseReceived('from web1.corp.local ([192.168.1.10]) by smtp.app.example.com with Microsoft SMTPSVC(7.5.7601.17514); Mon, 8 Jan 2018 16:02:46 -0600');
        expect(securityOf(iis)).toBe('unencrypted');
        expect(securityOf(parseReceived('from 1eYfVN-00004u-44 by in1.filter.example.com with hostsite:1000001 (Exim 4.87) id 1eYfVO-0000fI-4v; Mon, 08 Jan 2018 14:02:54 -0800'))).toBe('internal');
        expect(securityOf(parseReceived('by emcmailer; Mon, 08 Jan 2018 14:02:54 -0800'))).toBe('internal');
    });

    it('warns when a sender logs in without encryption, and separates private-network hops', () => {
        const route = buildRoute(
            splitMessage(
                [
                    'Received: from smtp.app.example.com ([203.0.113.78]) by in1.filter.example.com with esmtp (Exim 4.87) id 2; Mon, 08 Jan 2018 14:02:53 -0800',
                    'Received: from web1 ([192.168.1.10]) by smtp.app.example.com with Microsoft SMTPSVC(7.5.7601.17514); Mon, 8 Jan 2018 16:02:46 -0600',
                    'Received: from [198.51.100.219] (port=64995 helo=office1PC) by smtp.hosting.example.net with esmtpa (Exim 4.89_1) id 1; Mon, 8 Jan 2018 17:02:40 -0500',
                ].join('\n'),
            ).headers,
        );
        expect(route.hops[0].warnings[0]).toContain('logged in over an unencrypted connection');
        expect(route.warnings).toEqual([
            expect.stringContaining('2 hops were not encrypted (hops 1, 3)'),
            expect.stringContaining('inside a private network'),
        ]);
    });

    it('reads bracketed IPv6 address literals', () => {
        const r = parseReceived('from [IPv6:2001:db8::1] (unknown [IPv6:2001:db8::1]) by mx.example.org with ESMTPS id x; Mon, 5 Jan 2026 10:00:00 +0000');
        expect(r.from?.ip).toBe('2001:db8::1');
        expect(r.from?.noRdns).toBe(true);
    });
});

describe('analyze', () => {
    const ses = analyze(sesExim);

    it('builds the route bottom-up with delays', () => {
        const hops = ses.route.hops;
        expect(hops.map((h) => h.from?.rdns ?? h.from?.name)).toEqual(['a11-162.smtp-out.amazonses.com', 'spamwall.example.org', 'mail.hosting.example.net']);
        expect(hops.map((h) => h.by?.name)).toEqual(['spamwall.example.org', 'mail.hosting.example.net', 'mail.hosting.example.net']);
        expect(hops.map((h) => h.delay)).toEqual([null, 2, 1]);
        expect(hops.map((h) => h.security)).toEqual(['encrypted', 'encrypted', 'local']);
        expect(ses.route.totalSeconds).toBe(44);
        expect(ses.route.originIp).toBe('54.240.11.162');
    });

    it('recognises Amazon SES and groups its headers', () => {
        expect(ses.services[0].service.name).toBe('Amazon SES');
        const outgoing = ses.headers.find((h) => h.field.key === 'x-ses-outgoing')!;
        expect(outgoing.service).toBe('Amazon SES');
        expect(outgoing.facts.find((f) => f.label === 'SES outbound IP')?.value).toBe('54.240.11.162');
        const feedback = ses.headers.find((h) => h.field.key === 'feedback-id')!;
        expect(feedback.service).toBe('Amazon SES');
        expect(feedback.summary).toContain('US East (N. Virginia)');
        expect(feedback.facts[0]).toMatchObject({ label: 'AWS region', raw: 'us-east-1' });
        expect(feedback.facts.map((f) => f.label)).toEqual(['AWS region', 'Feedback loop sender', 'Campaign id', 'Customer id', 'Other id']);
    });

    it('decodes the send time hidden in SES message ids', () => {
        expect(formatUtc(sesTimestamp('010001a16b87e2b3-26f74ee6-4f88-48cc-8978-de87228e21df-000000')!)).toBe('2026-10-24 01:30:29 UTC');
        const messageId = ses.headers.find((h) => h.field.key === 'message-id')!;
        // Written in UTC, so no second UTC row.
        expect(messageId.facts.map((f) => f.label)).toEqual(expect.arrayContaining(['Sent by SES', 'Your time']));
        expect(messageId.facts.map((f) => f.label)).not.toContain('UTC');
    });

    it('summarises authentication and alignment', () => {
        expect(ses.auth.fromDomain).toBe('keymimestate.com');
        expect(ses.auth.spf).toMatchObject({ verdict: 'pass', domain: 'rsend.keymimestate.com', aligned: true });
        expect(ses.auth.dkimVerdict).toMatchObject({ verdict: 'pass', aligned: true });
        expect(ses.auth.dkimVerdict.domains).toEqual(['keymimestate.com', 'amazonses.com']);
        expect(ses.auth.dmarc).toMatchObject({ verdict: 'pass', policy: 'quarantine' });
    });

    it('decodes the subject and MIME parts', () => {
        expect(ses.subject).toBe('Your October statement is ready — Keymime');
        const parts = leafParts(ses.mime!);
        expect(parts.map((p) => [p.path, p.type])).toEqual([
            ['1', 'text/plain'],
            ['2', 'text/html'],
        ]);
        expect(parts[0].text).toContain('statement is ready — view it at https://keymimestate.com/statements/2026-10');
    });

    it('reads a Microsoft 365 message', () => {
        const a = analyze(m365);
        expect(a.route.hops).toHaveLength(6);
        expect(a.route.hops[0]).toMatchObject({ security: 'encrypted', authenticated: 'yes' });
        expect(a.route.hops[0].from?.ip).toBe('73.22.41.10');
        expect(a.route.hops[1].security).toBe('internal');
        expect(a.route.hops[5].security).toBe('encrypted');
        expect(a.auth.results[0].authservId).toBe('');
        expect(a.auth.dmarc.verdict).toBe('pass');
        const names = a.services.map((s) => s.service.name);
        expect(names).toContain('Microsoft (Exchange / Outlook)');
        expect(names).toContain('Google (Gmail / Workspace)');
        const forefront = a.headers.find((h) => h.field.key === 'x-forefront-antispam-report')!;
        expect(forefront.summary).toBe('Spam filtering verdict: Not spam.');
        expect(forefront.facts.find((f) => f.label === 'Spam Confidence Level (SCL)')).toMatchObject({ value: 'Not spam', raw: '1' });
        expect(forefront.facts.find((f) => f.label === 'Country/Region (CTRY)')?.value).toBe('US');
    });

    it('turns SpamAssassin rules into rows, in both list formats, using the report for descriptions', () => {
        const a = analyze(
            [
                'X-Spam-Status: No, hits=3.6 tagged_above=1 required=5 tests=[BAYES_99,',
                '\tRCVD_IN_UCEPROTECT1, SW_CUSTOM]',
                'X-Spam-Test-Scores: DKIM_SIGNED=0.1,DKIM_VALID=-0.1,MY_RULE=0.5',
                'X-Spam-Report:',
                '\t*  0.5 MY_RULE Something the admin wrote',
                'From: a@example.com',
            ].join('\n'),
        );
        const rules = (key: string) => a.headers.find((h) => h.field.key === key)!.rules;
        expect(rules('x-spam-status').map((r) => [r.name, r.points, !!r.meaning])).toEqual([
            ['BAYES_99', null, true],
            ['RCVD_IN_UCEPROTECT1', null, true],
            ['SW_CUSTOM', null, false],
        ]);
        expect(rules('x-spam-test-scores').map((r) => [r.name, r.points])).toEqual([
            ['DKIM_SIGNED', 0.1],
            ['DKIM_VALID', -0.1],
            ['MY_RULE', 0.5],
        ]);
        expect(rules('x-spam-test-scores')[2].meaning).toBe('Something the admin wrote');
        expect(rules('x-spam-status')[0].url).toBe('https://duckduckgo.com/?q=%22BAYES_99%22%20spamassassin');
    });
});

describe('who sent it and where to report it', () => {
    const network = (abuseEmail: string, organization: string) => ({ registry: 'ARIN', url: null, handle: 'NET-1', name: 'NET', country: null, range: null, cidrs: [], organization, abuseEmail, abusePhone: null });

    it('finds where the recipient took over, and which services were on the sending side', () => {
        const ses = analyze(sesExim);
        expect(ses.handoff).toBe(0);
        expect(ses.services.find((s) => s.service.name === 'Amazon SES')?.side).toBe('sending');

        const ms = analyze(m365);
        expect(ms.handoff).toBe(2);
        expect(ms.route.hops[2].from?.ip).toBe('209.85.220.41');
        expect(ms.services.find((s) => s.service.name === 'Google (Gmail / Workspace)')?.side).toBe('sending');
        expect(ms.services.find((s) => s.service.name === 'Microsoft (Exchange / Outlook)')?.side).toBe('receiving');
    });

    it("sees through a gateway's own content-filter loop (\"by localhost\") to the real sending server", () => {
        const a = analyze(spamwall);
        const handoff = a.route.hops[a.handoff!];
        expect(handoff.from?.ip).toBe('156.70.3.103');
        expect(checkQuery(a)).toMatchObject({ ip: '156.70.3.103', mailFrom: 'msprvs1=20759SRLLI8Ho=bounces-274689-4@bounce.eventbrite.com' });
        expect(a.route.hops.map((h) => h.security)).toEqual(['unencrypted', 'encrypted', 'local', 'local', 'encrypted', 'local']);
        // SparkPost's internal host name gives way to the public one the gateway saw.
        expect(buildStops(a.route, a.handoff).map((s) => [s.name, s.sender])).toEqual([
            ['10.90.8.225', false],
            ['mta-70-3-103.eventbrite.com.sparkpostmail.com', true],
            ['spamwall.example.org', false],
            ['mail.hosting.example.net', false],
        ]);
    });

    it("doesn't mistake the sender's own Exchange relaying to itself for the receiver's side", () => {
        const a = analyze(
            [
                'Received: from mx.example.org (mx.example.org [203.0.113.5]) by mail.example.org with ESMTPS id 1; Tue, 27 Oct 2026 11:23:57 -0400',
                'Received: from hybrid.sender.test (hybrid.sender.test [66.244.119.124]) (using TLSv1.2) by mx.example.org with ESMTPS id 2; Tue, 27 Oct 2026 11:22:49 -0400',
                'Received: from exch01.SENDER.local (10.0.3.25) by exch01.SENDER.local (10.0.3.25) with Microsoft SMTP Server (version=TLS1_2) id 15.2; Tue, 27 Oct 2026 11:22:46 -0400',
                'Received: from Web5 (10.0.9.154) by exch01.SENDER.local (10.0.3.25) with Microsoft SMTP Server id 15.2 via Frontend Transport; Tue, 27 Oct 2026 11:22:46 -0400',
                'From: a@sender.test',
                'To: b@example.org',
            ].join('\n'),
        );
        expect(a.route.hops[a.handoff!].from?.ip).toBe('66.244.119.124');
        expect(checkQuery(a).ip).toBe('66.244.119.124');
        // The Exchange server is shown under its public name, with its internal one kept, and marked as the sender.
        const stops = buildStops(a.route, a.handoff);
        expect(stops.map((s) => s.name)).toEqual(['Web5', 'hybrid.sender.test', 'mx.example.org', 'mail.example.org']);
        expect(stops[1]).toMatchObject({ ip: '66.244.119.124', internal: { name: 'exch01.SENDER.local', ip: '10.0.3.25' }, sender: true });
    });

    it('sends SES abuse to Amazon, quoting the account ids, and merges the matching network owner', () => {
        const a = analyze(sesExim);
        expect(networkTargets(a)).toEqual(['54.240.11.162']);
        const report = senderReport(a, { '54.240.11.162': network('email-abuse@amazon.com', 'Amazon Web Services, Inc.') });
        expect(report.targets[0]).toMatchObject({ who: 'Amazon SES', email: 'email-abuse@amazon.com' });
        expect(report.targets[0].quote.map((q) => q.name)).toEqual(['Feedback-ID', 'Message-ID']);
        expect(report.targets[0].why).toContain('Also the registered abuse contact for 54.240.11.162');
        expect(report.targets.filter((t) => t.source === 'registry')).toHaveLength(0);
        expect(report.findings).toEqual([]);
        // The summary names the service and its ids, not the raw headers.
        const service = report.actual.find((i) => i.label === 'Sent through')!;
        expect(service.value).toBe('Amazon SES');
        expect(service.details?.map((d) => d.label)).toEqual(['Kind', 'Customer id', 'Other id']);
        expect(report.actual.some((i) => i.label === 'Sending server')).toBe(false);
    });

    it('reports the sending mailbox provider and the networks, not the recipient\'s own provider', () => {
        const a = analyze(m365);
        const report = senderReport(a, { '209.85.220.41': network('network-abuse@google.com', 'Google LLC'), '73.22.41.10': network('abuse@comcast.net', 'Comcast Cable') });
        const who = report.targets.map((t) => t.who);
        expect(who[0]).toBe('Google (Gmail / Workspace)');
        expect(who).not.toContain('Microsoft (Exchange / Outlook)');
        expect(who).toContain('Google LLC');
        expect(who).toContain('Comcast Cable');
        expect(who).not.toContain('The registrar of gmail.com');
        expect(report.actual.find((i) => i.label === 'Sent through')?.value).toBe('Google (Gmail / Workspace)');
    });

    it('flags an account that logged in as someone other than the From address', () => {
        const a = analyze(
            [
                'Received: from [198.51.100.9] (Authenticated sender: bob@cheap-host.example) by smtp.cheap-host.example with ESMTPSA id 1; Mon, 5 Jan 2026 10:00:00 +0000',
                'From: "PayPal Support" <service@paypal.com>',
                'To: you@example.org',
                'Subject: Your account is limited',
            ].join('\n'),
        );
        const report = senderReport(a, null);
        expect(report.actual[0]).toMatchObject({ label: 'Genuine?', tone: 'warn', value: 'Unproven: nothing ties it to paypal.com' });
        expect(report.actual[1]).toMatchObject({ label: 'Account', value: 'bob@cheap-host.example' });
        expect(report.actual.find((i) => i.label === 'Sending server')?.value).toBe('198.51.100.9');
        expect(report.findings[0]).toMatchObject({ tone: 'bad', text: expect.stringContaining('Sent by the account bob@cheap-host.example, but the From address claims service@paypal.com') });
    });
});

describe('explaining authentication headers part by part', () => {
    it('explains every property, comment and extra method in Authentication-Results', () => {
        const a = analyze(
            [
                'Authentication-Results: dkim.mail-tester.com;',
                '\tdkim=pass (2048-bit key; unprotected) header.d=example.com header.i=@example.com header.a=rsa-sha256 header.s=default header.b=PL0PsWfu;',
                '\tdkim-atps=neutral',
                'Authentication-Results: mail-tester.com; dmarc=pass (p=none dis=none) header.from=example.com',
                'From: a@example.com',
            ].join('\n'),
        );
        // Every row: "Name (code)" with the decoded value, the raw value kept for the tooltip.
        const facts = a.headers.flatMap((h) => h.facts);
        const row = (label: string) => facts.find((f) => f.label === label);
        expect(row('Signature Prefix (header.b)')).toMatchObject({ value: 'PL0PsWfu' });
        expect(row('Signing Domain (header.d)')).toMatchObject({ value: 'example.com', kind: 'domain' });
        expect(row('Key Size')).toMatchObject({ value: '2048 bits' });
        expect(row('DKIM Authorized Third-Party Signatures (dkim-atps)')).toMatchObject({ value: 'Neutral', raw: 'neutral' });
        expect(row('Disposition (dis)')).toMatchObject({ value: 'Delivered normally', raw: 'none' });
        expect(row('Published Policy (p)')).toMatchObject({ value: 'None (monitor only)', raw: 'none' });
        expect(facts.some((f) => / — |·/.test(`${f.label}${f.value}`))).toBe(false);
    });

    it('lists DKIM-Signature tags in the order written, as "Name (tag)" rows', () => {
        const dkim = analyze(sesExim).headers.find((h) => h.field.key === 'dkim-signature')!;
        expect(dkim.facts.slice(0, 4).map((f) => f.label)).toEqual(['Version (v)', 'Algorithm (a)', 'Query Method (q)', 'Canonicalization (c)']);
        expect(dkim.facts[1]).toMatchObject({ value: 'RSA with SHA-256', raw: 'rsa-sha256' });
        expect(dkim.facts.find((f) => f.label === 'Signing Domain (d)')).toMatchObject({ kind: 'domain' });
        expect(dkim.facts.map((f) => f.label)).toContain('Key location');
    });

    it('breaks down Exchange server names, encoded subjects, and gives every header a labelled row', () => {
        const a = analyze(
            [
                'X-MS-TrafficTypeDiagnostic: MW4PR04MB7380:EE_|BN7NAM10FT063:EE_',
                'X-Microsoft-Antispam: BCL:0;ARA:13230040|4022899009;',
                'MIME-Version: 1.0',
                'X-Some-Unknown: hello',
                `Subject: =?utf-8?Q?Caf=C3=A9_menu?=`,
                sesExim.replace(/^Subject:.*\n/m, ''),
            ].join('\n'),
        );
        const facts = (key: string) => a.headers.find((h) => h.field.key === key)!.facts;
        const traffic = facts('x-ms-traffictypediagnostic');
        expect(traffic.filter((f) => f.label === 'Server').map((f) => f.value)).toEqual(['MW4PR04MB7380', 'BN7NAM10FT063']);
        expect(traffic.find((f) => f.label === 'Role')?.value).toBe('Mailbox server');
        expect(traffic.find((f) => f.label === 'Forest' && f.raw === 'NAM10')?.value).toBe('North America');
        expect(facts('x-microsoft-antispam').find((f) => f.label === 'Anti-spam Rules Applied (ARA)')).toMatchObject({ value: '2 matched', raw: '13230040|4022899009' });
        expect(facts('mime-version')).toEqual([{ label: 'Version', value: '1.0' }]);
        expect(facts('x-some-unknown')).toEqual([{ label: 'Value', value: 'hello' }]);
        const subject = facts('subject');
        expect(subject[0]).toMatchObject({ label: 'Text', value: 'Café menu' });
        expect(subject.find((f) => f.label === 'Character set')?.value).toBe('UTF-8');
        expect(subject.find((f) => f.label === 'Encoding')?.value).toBe('Quoted-printable');
    });

    it('unscrambles OVH X-VR-SPAMCAUSE', () => {
        // Encode by finding, for each character, a letter pair that decodes to it.
        const letters = 'abcdefghijklmnopqrstuvwxyz';
        const encode = (text: string) =>
            [...text]
                .map((ch) => {
                    for (const a of letters) for (const b of letters) if (decodeSpamcause(a + b) === ch) return a + b;
                    throw new Error(`no pair for ${ch}`);
                })
                .join('');
        const plain = 'gggruggvucftvghtrhhoucdtuddrfeelgedrvdduucetufdoteggodetrfcurfhrohhfihhlvgemucfqggfjpdevjffgvefmvefgne';
        expect(decodeSpamcause(encode('rule: SPAM; score: 7'))).toBe('rule: SPAM; score: 7');
        expect(decodeSpamcause(plain)).not.toBeNull();
        const a = analyze(`X-VR-SPAMCAUSE: ${encode('score: 7; rule: SPAM')}\n${sesExim}`);
        expect(a.headers.find((h) => h.field.key === 'x-vr-spamcause')!.facts).toEqual([
            { label: 'score', value: '7', mono: true },
            { label: 'rule', value: 'SPAM', mono: true },
        ]);
    });

    it('labels Microsoft rule ids it can, and finds the original sender behind a gateway', () => {
        const a = analyze(
            [
                'X-Microsoft-Antispam: BCL:0;ARA:35100500006|4022899009;',
                'X-MS-Exchange-ExternalOriginalInternetSender: ip=[203.0.113.5];domain=mail.spammer.example',
                sesExim,
            ].join('\n'),
        );
        const ara = a.headers.find((h) => h.field.key === 'x-microsoft-antispam')!.facts.filter((f) => f.label === 'Rule');
        expect(ara).toEqual([
            expect.objectContaining({ value: 'Probably: Embedded image', raw: '35100500006' }),
            expect.objectContaining({ value: 'Unknown', raw: '4022899009' }),
        ]);
        const original = a.headers.find((h) => h.field.key === 'x-ms-exchange-externaloriginalinternetsender')!.facts;
        expect(original[0]).toMatchObject({ label: 'Original Sender IP (ip)', value: '203.0.113.5', kind: 'ip' });
        expect(originalSender(a)).toEqual({ ip: '203.0.113.5', domain: 'mail.spammer.example' });
        expect(networkTargets(a)[0]).toBe('203.0.113.5');

        // Not on the Received path: it becomes the first stop, and the sending server instead of the gateway.
        const stops = buildStops(a.route, a.handoff);
        expect(stops[0]).toMatchObject({ name: 'mail.spammer.example', ip: '203.0.113.5', original: 'record-only', sender: true, hopIn: null });
        expect(stops.filter((s) => s.sender)).toHaveLength(1);
        expect(lookupTargets(a.route).ips).toContain('203.0.113.5');

        // Already on the path: that stop is marked, nothing is added.
        const onPath = analyze(`X-MS-Exchange-ExternalOriginalInternetSender: ip=[54.240.11.162];domain=a.example\n${sesExim}`);
        const marked = buildStops(onPath.route, onPath.handoff);
        expect(marked).toHaveLength(buildStops(analyze(sesExim).route, null).length);
        expect(marked.find((s) => s.original)).toMatchObject({ ip: '54.240.11.162', original: 'received', sender: true });
    });

    it('reads the address out of X-Report-Abuse', () => {
        const report = analyze(`X-Report-Abuse: <mailto:abuse@example.com>\n${sesExim}`).headers.find((h) => h.field.key === 'x-report-abuse')!;
        expect(report.facts).toEqual([{ label: 'Email', value: 'abuse@example.com', kind: 'email' }]);
    });
});

describe('DKIM verification', () => {
    it('canonicalizes like RFC 6376 §3.4.6', () => {
        expect(canonicalizeHeader('A: X', 'relaxed') + canonicalizeHeader('B : Y\t\n\tZ  ', 'relaxed')).toBe('a:Xb:Y Z');
        expect(canonicalizeBody(' C \nD \t E\n\n\n', 'relaxed')).toBe(' C\r\nD E\r\n');
        expect(canonicalizeBody(' C \nD \t E\n\n\n', 'simple')).toBe(' C \r\nD \t E\r\n');
        expect(canonicalizeBody('', 'simple')).toBe('\r\n');
        expect(canonicalizeBody('\n\n', 'relaxed')).toBe('');
    });

    it('verifies the RFC 8463 Ed25519 example (including a header listed twice in h=)', async () => {
        const m = splitMessage(rfc8463);
        const signature = summarizeAuth(m.headers).dkim[0];
        const key = { publicKey: '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=', keyType: 'ed25519' };
        expect(await verifyDkim(signature, m.headers, m.body, key)).toMatchObject({ bodyHashOk: true, signatureOk: true, error: null });

        const tampered = splitMessage(rfc8463.replace('Is dinner ready?', 'Is lunch ready?').replace('Joe.', 'Bob.'));
        expect(await verifyDkim(summarizeAuth(tampered.headers).dkim[0], tampered.headers, tampered.body, key)).toMatchObject({ bodyHashOk: false, signatureOk: false });
    });

    it('ignores blank lines a mail app added between the headers and the body when saving', async () => {
        const saved = splitMessage(rfc8463.replace(/\r?\n\r?\n/, '\n\n\n\n'));
        const result = await verifyDkim(summarizeAuth(saved.headers).dkim[0], saved.headers, saved.body, { publicKey: '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=', keyType: 'ed25519' });
        expect(result).toMatchObject({ bodyHashOk: true, signatureOk: true });
        expect(result.bodyNote).toContain('2 blank lines');
    });
});

describe('message parsing', () => {
    it('unfolds headers and accepts a headers-only paste', () => {
        const m = splitMessage('Subject: one\n\ttwo\nFrom: a@b.c\n');
        expect(m.headers.map((h) => h.value)).toEqual(['one two', 'a@b.c']);
        expect(m.hasBody).toBe(false);
    });

    it('rejects text that is not an email', () => {
        expect(() => splitMessage('Hello there, how are you?')).toThrow(NotAnEmailError);
    });

    it('decodes RFC 2047 words, joining split multi-byte characters', () => {
        expect(decodeEncodedWords('=?UTF-8?B?w6k=?= =?UTF-8?Q?t=C3=A9?=')).toBe('été');
        expect(decodeEncodedWords('=?UTF-8?B?w6k=?= plain')).toBe('é plain');
        expect(decodeEncodedWords('=?ISO-8859-1?Q?caf=E9?=')).toBe('café');
        expect(new TextDecoder().decode(decodeQuotedPrintable('a=3Db=\nc'))).toBe('a=bc');
    });

    it('parses address lists and groups', () => {
        expect(parseAddressList('"Doe, Jane" <jane@example.com>, bob@example.org (Bob)')).toEqual([
            { name: 'Doe, Jane', address: 'jane@example.com', domain: 'example.com' },
            { name: 'Bob', address: 'bob@example.org', domain: 'example.org' },
        ]);
        expect(parseAddressList('undisclosed-recipients:;')).toEqual([]);
        expect(parseAddressList('Team: a@x.com, b@y.com;').map((m) => m.address)).toEqual(['a@x.com', 'b@y.com']);
    });

    it('parses the date formats mailers write', () => {
        expect(parseDate('Thu, 08 Jan 2026 07:22:37 -0800 (PST)')?.time).toBe(Date.UTC(2026, 0, 8, 15, 22, 37));
        expect(parseDate('8 Jan 26 15:22 GMT')?.time).toBe(Date.UTC(2026, 0, 8, 15, 22));
        expect(parseDate('Thu, 8 Jan 2026 10:22:25 EST')?.offset).toBe(-300);
        expect(parseDate('2026-01-08T15:22:37Z')?.time).toBe(Date.UTC(2026, 0, 8, 15, 22, 37));
        expect(parseDate('garbage')).toBeNull();
    });
});

describe('authentication helpers', () => {
    it('parses Authentication-Results with and without an authserv-id', () => {
        const google = parseAuthResults(field('Authentication-Results', 'mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b=abc; spf=pass (google.com: domain of x@example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=x@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com'));
        expect(google.authservId).toBe('mx.google.com');
        expect(google.results.map((r) => `${r.method}=${r.result}`)).toEqual(['dkim=pass', 'spf=pass', 'dmarc=pass']);
        expect(google.results[2].comment).toBe('p=REJECT sp=REJECT dis=NONE');
    });

    it('falls back to ARC results when the receiver recorded none, and says so', () => {
        const auth = summarizeAuth(
            splitMessage(
                [
                    'ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none; b=abc',
                    'ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass smtp.mailfrom=news.example.com; dmarc=pass action=none header.from=example.com; dkim=pass header.d=example.com; arc=none',
                    'Return-Path: <bounce@news.example.com>',
                    'From: Example <hello@example.com>',
                    'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from:to:subject; bh=x; b=y',
                ].join('\n'),
            ).headers,
        );
        expect(auth.spf).toMatchObject({ verdict: 'pass', domain: 'news.example.com', aligned: true });
        expect(auth.dkimVerdict).toMatchObject({ verdict: 'pass', aligned: true });
        expect(auth.dmarc).toMatchObject({ verdict: 'pass', source: { server: 'mx.microsoft.com', arc: 1 } });
        expect(sourceLabel(auth.dmarc.source)).toBe('mx.microsoft.com (recorded in ARC, hop 1)');
    });

    it("prefers the receiver's own results over ARC", () => {
        const auth = summarizeAuth(
            splitMessage(
                [
                    'Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=example.com',
                    'ARC-Authentication-Results: i=1; mx.google.com; spf=pass smtp.mailfrom=example.com',
                    'From: a@example.com',
                ].join('\n'),
            ).headers,
        );
        expect(auth.spf).toMatchObject({ verdict: 'fail', source: { server: 'mx.example.org', arc: null } });
    });

    it("fills in what no server recorded from the live checks, but keeps what was recorded", () => {
        const auth = summarizeAuth(splitMessage('Received-SPF: Fail (mx.example.org: …) client-ip=192.0.2.1;\nReturn-Path: <b@example.com>\nFrom: a@example.com\n').headers);
        const live = {
            checks: { spf: { result: 'pass', domain: 'example.com', ip: '192.0.2.1' }, dmarc: { found: true, tags: { p: 'reject' } } },
            dkim: [],
            dmarc: { result: 'pass' },
        } as unknown as LiveAuth;
        const merged = withLive(auth, live);
        expect(merged.spf).toMatchObject({ verdict: 'fail', source: { server: 'mx.example.org' } }); // recorded on arrival: kept
        expect(merged.dmarc).toMatchObject({ verdict: 'pass', policy: 'reject', source: { live: true } }); // not recorded: filled in
        expect(sourceLabel(merged.dmarc.source)).toContain('just now');
    });

    it('flags an ARC pass for a DKIM signature the message does not contain, and a DMARC pass that fails now', () => {
        const auth = summarizeAuth(
            splitMessage(
                [
                    'ARC-Authentication-Results: i=1; mx.zohomail360.eu; dkim=pass header.i=victim.fr; spf=pass smtp.mailfrom=bounce@mailer.example.com; dmarc=pass header.from=<info@victim.fr>',
                    'DKIM-Signature: v=1; a=rsa-sha256; d=mailer.example.com; s=s1; h=from; bh=x; b=y',
                    'From: info@victim.fr',
                ].join('\n'),
            ).headers,
        );
        expect(auth.dkimVerdict.domains).toEqual(['victim.fr']); // bare header.i, no "@"
        const live = {
            checks: { spf: { result: 'pass', domain: 'mailer.example.com', ip: '192.0.2.1' }, dmarc: { found: true, tags: { p: 'none' } } },
            dkim: [{ signature: auth.dkim[0], valid: true }],
            dmarc: { result: 'fail' },
        } as unknown as LiveAuth;
        const conflicts = authConflicts(auth, live);
        expect(conflicts.map((c) => [c.method, c.strong])).toEqual([
            ['DKIM', true],
            ['DMARC', true],
        ]);
        expect(conflicts[0].text).toContain('no signature from victim.fr (only from mailer.example.com)');
    });

    it('never calls an unchecked domain aligned', () => {
        const auth = summarizeAuth(splitMessage('Return-Path: <a@example.com>\nFrom: b@example.com\n').headers);
        expect(auth.spf).toMatchObject({ verdict: 'unknown', aligned: false, domainMatches: true });
    });

    it('finds the organisational domain', () => {
        expect(organizationalDomain('mail.news.example.co.uk')).toBe('example.co.uk');
        expect(organizationalDomain('rsend.keymimestate.com')).toBe('keymimestate.com');
    });

    it('decodes Outlook Thread-Index timestamps', () => {
        const decoded = decodeThreadIndex('AQHbYdQ3Ihb7XUhzzkOJ1C7gB0n5Bg==');
        expect(decoded?.replies).toBe(0);
        expect(new Date(decoded!.started!).getUTCFullYear()).toBeGreaterThanOrEqual(2024);
    });
});

describe('look-alike text', () => {
    it('spots Cyrillic letters disguised as Latin, but not real Cyrillic text', () => {
        const fake = checkText('Ѕtоrаgе Support');
        expect(fake).toMatchObject({ mixed: true, reads: 'Storage Support' });
        expect(fake.odd.map((o) => o.looksLike)).toEqual(['S', 'o', 'a', 'e']);
        expect(checkText('Иван Петров').odd).toEqual([]);
        expect(checkText('Café Müller').odd).toEqual([]);
    });

    it('spots styled and invisible characters', () => {
        expect(checkText('𝐒𝐭𝐨𝐫𝐚𝐠𝐞').reads).toBe('Storage');
        expect(checkText('pay\u200Bpal')).toMatchObject({ invisible: true, reads: 'paypal' });
    });

    it('decodes punycode domains', () => {
        expect(decodeDomain('xn--mnchen-3ya.de')).toBe('münchen.de');
        expect(decodeDomain('xn--pypal-4ve.com')).toBe('pаypal.com');
        expect(decodeDomain('example.com')).toBeNull();
    });

    it('checks the sender, reply-to, subject and envelope domains', () => {
        const a = analyze(['From: "Ѕtоrаgе Support" <info@example.fr>', 'Reply-To: "Ѕtоrаgе Support" <x@xn--pypal-4ve.com>', 'Subject: Hello', 'Return-Path: <b@example.fr>'].join('\n'));
        const found = findLookalikes(a);
        expect(found.map((f) => f.where)).toEqual(['From display name and Reply-To display name', 'Reply-To address']);
        expect(found[1]).toMatchObject({ shown: 'x@pаypal.com', punycode: 'xn--pypal-4ve.com' });
    });
});

describe('Outlook .msg files', () => {
    it('unwraps the HTML that Outlook keeps inside an RTF body', () => {
        const BACKSLASH = String.fromCharCode(92);
        const rtf = [
            String.raw`{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl{\f0\fswiss Arial;}}`,
            String.raw`{\*\htmltag19 <html>}{\*\htmltag3 \par }`,
            String.raw`{\*\htmltag64 <p class="x">}\htmlrtf {\b \htmlrtf0 Caf\'e9 \{ok\} ${BACKSLASH}u8364?5\htmlrtf \par }\htmlrtf0 `,
            String.raw`{\*\mhtmltag84 <img src="image001.png">}{\*\htmltag84 <img src="cid:image001.png">}`,
            String.raw`{\*\htmltag72 </p>}{\*\htmltag27 </html>}}`,
        ].join('\r\n');
        expect(htmlFromRtf(rtf)).toBe('<html>\r\n<p class="x">Café {ok} €5<img src="cid:image001.png"></p></html>');
        expect(htmlFromRtf(String.raw`{\rtf1\ansi\fromtext Plain}`)).toBeNull();
    });

    const msg = (fields: Omit<MsgSource['fields'], 'dataType'>, files: Record<string, Uint8Array | MsgSource> = {}): MsgSource => ({
        fields: { ...fields, dataType: 'msg' },
        content: (a) => {
            const file = files[a.name ?? ''];
            if (!file) throw new Error('no data');
            return file instanceof Uint8Array ? file : new TextEncoder().encode(a.name);
        },
        open: (bytes) => files[new TextDecoder().decode(bytes)] as MsgSource,
        rtf: (compressed) => new TextDecoder().decode(compressed),
    });

    it('puts the headers, both bodies and the attachments back together as MIME', () => {
        const inner = msg({ senderName: 'Bob', senderSmtpAddress: 'bob@example.com', subject: 'Inner', recipients: [{ dataType: 'recipient', name: 'Al', smtpAddress: 'al@example.org', recipType: 'to' }], body: 'Inner body' });
        const rebuilt = msgToEml(
            msg(
                {
                    headers: 'Received: from mx.example.com by mx.example.org; Mon, 5 Jan 2026 10:00:00 +0000\r\nFrom: Ann <ann@example.com>\r\nSubject: Hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative;\r\n\tboundary="original"\r\n\r\n',
                    body: 'Hello\r\nthere',
                    compressedRtf: new TextEncoder().encode(String.raw`{\rtf1\ansi\fromhtml1 {\*\htmltag19 <p>Hello <img src="cid:logo@1"></p>}}`),
                    attachments: [
                        { dataType: 'attachment', name: 'logo.png', fileName: 'logo.png', pidContentId: 'logo@1', attachmentHidden: true },
                        { dataType: 'attachment', name: 'reçu.pdf', fileName: 'reçu.pdf' },
                        { dataType: 'attachment', name: 'Inner', innerMsgContent: true },
                        { dataType: 'attachment', name: 'Linked object' },
                    ],
                },
                { 'logo.png': Uint8Array.of(0x89, 0x50, 0x4e, 0x47), 'reçu.pdf': new TextEncoder().encode('%PDF'), Inner: inner },
            ),
        );
        expect(rebuilt.attachments).toEqual(['logo.png', 'reçu.pdf', 'Inner.msg']);
        expect(rebuilt.skipped).toEqual(['Linked object']);
        expect(rebuilt.source).not.toContain('boundary="original"');

        const a = analyze(rebuilt.source, { bodyRebuilt: true });
        expect(a.bodyRebuilt).toBe(true);
        expect(a.subject).toBe('Hi');
        expect(a.route.hops).toHaveLength(1);
        expect(a.mime?.type).toBe('multipart/mixed');
        const parts = leafParts(a.mime!);
        expect(parts.map((p) => [p.type, p.filename, p.contentId])).toEqual([
            ['text/plain', null, null],
            ['text/html', null, null],
            ['image/png', 'logo.png', 'logo@1'],
            ['application/pdf', 'reçu.pdf', null],
            ['message/rfc822', 'Inner.eml', null],
        ]);
        expect(parts[0].text).toBe('Hello\nthere');
        expect(parts[1].text).toBe('<p>Hello <img src="cid:logo@1"></p>');
        expect(parts[2].size).toBe(4);
        expect(parts[2].disposition).toBe('inline');

        // An attached Outlook item with no internet headers gets them from Outlook's own fields.
        const attached = analyze(parts[4].message!);
        expect(attached.from).toMatchObject({ name: 'Bob', address: 'bob@example.com' });
        expect(attached.to[0]).toMatchObject({ name: 'Al', address: 'al@example.org' });
        expect(attached.subject).toBe('Inner');
        expect(leafParts(attached.mime!)[0].text).toBe('Inner body');
    });

    it("doesn't hold a rebuilt body against the DKIM signature", async () => {
        const [signature] = summarizeAuth(splitMessage(rfc8463).headers).dkim;
        const result = await verifyDkim(signature, [], null, { publicKey: null, keyType: 'rsa' }, 'Rebuilt from Outlook.');
        expect(result).toMatchObject({ bodyHashOk: null, bodyNote: 'Rebuilt from Outlook.' });
    });
});

describe('link redirects', () => {
    it('finds where protection and tracking wrappers really go', () => {
        expect(unwrapLink('https://linkprotect.cudasvc.com/url?a=http%3a%2f%2fwww.erie.pa.us&c=E,1,-zqw773r9ZVhpkuRuuxn-5kOG8risz5ZtVMKJ9GxVa-o3V_XNe5gfg1BlPSN7UYmyBxuuddn18AuhBFYjmHPxkzaKmqQUUUzINxZvYb3OlF4vEP3EQ,,&typo=1')).toBe('http://www.erie.pa.us');
        expect(unwrapLink('https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fpay%3Fid%3D1&data=05%7C01&reserved=0')).toBe('https://example.com/pay?id=1');
        expect(unwrapLink('https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_path-3Fa-3D1&d=DwMF&c=x')).toBe('https://example.com/path?a=1');
        expect(unwrapLink('https://urldefense.com/v3/__https://example.com/login__;!!ABC123$')).toBe('https://example.com/login');
        expect(unwrapLink('https://www.google.com/url?q=https://example.org/&sa=D')).toBe('https://example.org/');
        expect(unwrapLink('https://vwbrw9dy.r.us-east-1.awstrack.me/L0/https:%2F%2Fawsworkshop.io%2Feks%2Fsaas%3Ftrk=ac0635b0-d034-40d7-bb5a-68e7d8058160%26sc_channel=el/2/010001a1a2706a15-a964f547-9239-4d3f-ab3b-09f8def0cb78-000000/yQI88k2cji1KlOVOF3o9HGa4Ahg=473')).toBe('https://awsworkshop.io/eks/saas?trk=ac0635b0-d034-40d7-bb5a-68e7d8058160&sc_channel=el');
        // Only Amazon's own domain gets this reading
        expect(unwrapLink('https://awstrack.me.example.com/L0/https:%2F%2Fexample.org%2F/2/x/y')).toBeNull();
        // Safe Links around Proofpoint
        const inner = 'https://urldefense.com/v3/__https://example.net/__;!!x$';
        expect(unwrapLink(`https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent(inner)}`)).toBe('https://example.net/');
        expect(unwrapLink('https://example.com/page?id=5')).toBeNull();
    });
});

describe('tokenizeHtml', () => {
    it('splits tags, attributes, comments and entities without losing text', async () => {
        const { tokenizeHtml } = await import('./highlight');
        const src = '<!doctype html><!-- hi --><a href="x>y" data-x=1 hidden>Tom &amp; Jerry</a><br/> 1 < 2';
        const tokens = tokenizeHtml(src);
        expect(tokens.map((t) => t.text).join('')).toBe(src);
        expect(tokens.filter((t) => t.kind === 'tag').map((t) => t.text)).toEqual(['a', 'a', 'br']);
        expect(tokens.filter((t) => t.kind === 'attr').map((t) => t.text)).toEqual(['href', 'data-x', 'hidden']);
        expect(tokens.filter((t) => t.kind === 'value').map((t) => t.text)).toEqual(['"x>y"', '1']);
        expect(tokens.find((t) => t.kind === 'entity')?.text).toBe('&amp;');
        expect(tokens.find((t) => t.kind === 'comment')?.text).toBe('<!-- hi -->');
    });
});
