<?php

declare(strict_types=1);

namespace EmailReader\Tests\Unit;

use EmailReader\Checks\CheckRequest;
use EmailReader\Checks\DkimKeys;
use EmailReader\Checks\DmarcCheck;
use EmailReader\Checks\HostChecks;
use EmailReader\Checks\SpfEvaluator;
use EmailReader\Tests\FakeDns;
use PHPUnit\Framework\TestCase;

final class AuthChecksTest extends TestCase
{
    private function spf(array $zone, string $ip, string $domain = 'example.com'): array
    {
        return (new SpfEvaluator(new FakeDns($zone)))->check($ip, $domain, "bounce@{$domain}", 'mail.example.com');
    }

    public function testMatchesThroughIncludeAndRecordsTheTrace(): void
    {
        $zone = [
            'example.com|TXT' => FakeDns::txt('v=spf1 ip4:192.0.2.0/24 include:_spf.esp.test -all'),
            '_spf.esp.test|TXT' => FakeDns::txt('v=spf1 ip4:198.51.100.0/24 ~all'),
        ];
        $result = $this->spf($zone, '198.51.100.7');

        self::assertSame('pass', $result['result']);
        self::assertSame(1, $result['lookups']);
        $terms = $result['trace']['terms'];
        self::assertFalse($terms[0]['matched']);
        self::assertTrue($terms[1]['matched']);
        self::assertSame('pass', $terms[1]['child']['result']);
        self::assertNull($terms[2]['matched'], 'terms after the match are not evaluated');
    }

    public function testQualifiersAndFallthrough(): void
    {
        $zone = ['example.com|TXT' => FakeDns::txt('v=spf1 a mx ~all'), 'example.com|A' => FakeDns::a('192.0.2.1'), 'example.com|MX' => []];
        self::assertSame('softfail', $this->spf($zone, '203.0.113.9')['result']);
        self::assertSame('pass', $this->spf($zone, '192.0.2.1')['result']);
        self::assertSame('neutral', $this->spf(['example.com|TXT' => FakeDns::txt('v=spf1 ip4:192.0.2.1')], '203.0.113.9')['result']);
    }

    public function testRedirectAndMacros(): void
    {
        $zone = [
            'example.com|TXT' => FakeDns::txt('v=spf1 exists:%{ir}.%{l}._spf.example.com redirect=_spf.example.net'),
            '7.100.51.198.bounce._spf.example.com|A' => FakeDns::a('127.0.0.2'),
            '_spf.example.net|TXT' => FakeDns::txt('v=spf1 -all'),
        ];
        self::assertSame('pass', $this->spf($zone, '198.51.100.7')['result']);
        self::assertSame('fail', $this->spf($zone, '198.51.100.8')['result']);
    }

    public function testErrors(): void
    {
        self::assertSame('none', $this->spf([], '192.0.2.1')['result']);
        self::assertSame('permerror', $this->spf(['example.com|TXT' => FakeDns::txt('v=spf1 -all', 'v=spf1 +all')], '192.0.2.1')['result']);
        self::assertSame('permerror', $this->spf(['example.com|TXT' => FakeDns::txt('v=spf1 ip4:bogus/99 foo:bar -all')], '192.0.2.1')['result']);
        self::assertSame('temperror', $this->spf(['example.com|TXT' => 'SERVFAIL'], '192.0.2.1')['result']);

        // Eleven includes: past the 10-lookup limit.
        $zone = ['example.com|TXT' => FakeDns::txt('v=spf1 ' . implode(' ', array_map(fn ($i) => "include:i{$i}.test", range(1, 11))) . ' -all')];
        foreach (range(1, 11) as $i) {
            $zone["i{$i}.test|TXT"] = FakeDns::txt('v=spf1 ip4:203.0.113.0/24 -all');
        }
        $result = $this->spf($zone, '192.0.2.1');
        self::assertSame('permerror', $result['result']);
        self::assertStringContainsString('10 DNS lookups', (string) $result['explanation']);
    }

    public function testIpv6Ranges(): void
    {
        $zone = ['example.com|TXT' => FakeDns::txt('v=spf1 ip6:2001:db8::/32 -all')];
        self::assertSame('pass', $this->spf($zone, '2001:db8::25')['result']);
        self::assertSame('fail', $this->spf($zone, '192.0.2.1')['result']);
    }

    public function testDmarcWarningsAndReportAuthorisation(): void
    {
        $dns = new FakeDns([
            '_dmarc.example.com|TXT' => FakeDns::txt('v=DMARC1; p=none; pct=50; rua=mailto:dmarc@example.com,mailto:reports@vendor.test'),
        ]);
        $result = (new DmarcCheck($dns))->check('mail.example.com', 'example.com');

        self::assertTrue($result['found']);
        self::assertTrue($result['inherited'], 'falls back to the organisational domain');
        self::assertTrue($result['valid']);
        self::assertCount(3, $result['warnings']); // p=none, pct=50, vendor.test not authorised
        self::assertSame([true, false], array_column($result['reports'], 'authorized'));
        self::assertContains('example.com._report._dmarc.vendor.test|TXT', $dns->asked);
    }

    public function testDmarcErrorsAndMissingRecord(): void
    {
        $bad = (new DmarcCheck(new FakeDns(['_dmarc.example.com|TXT' => FakeDns::txt('v=DMARC1; p=block; aspf=x')])))->check('example.com', 'example.com');
        self::assertFalse($bad['valid']);
        self::assertCount(2, $bad['errors']);

        $none = (new DmarcCheck(new FakeDns([])))->check('example.com', 'example.com');
        self::assertFalse($none['found']);
        self::assertStringContainsString('No DMARC record', $none['errors'][0]);

        $missingRua = (new DmarcCheck(new FakeDns(['_dmarc.example.com|TXT' => FakeDns::txt('v=DMARC1; p=reject')])))->check('example.com', 'example.com');
        self::assertStringContainsString('No rua=', $missingRua['warnings'][0]);
    }

    public function testDkimKeysAndForwardConfirmedReverseDns(): void
    {
        $dns = new FakeDns([
            's1._domainkey.example.com|TXT' => FakeDns::txt('v=DKIM1; k=ed25519; t=y; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='),
            '1.2.0.192.in-addr.arpa|PTR' => [['target' => 'mail.example.com']],
            'mail.example.com|A' => FakeDns::a('192.0.2.1'),
        ]);
        [$key, $missing] = (new DkimKeys($dns))->fetch([['d' => 'example.com', 's' => 's1'], ['d' => 'example.com', 's' => 'gone']]);
        self::assertSame(['found' => true, 'keyType' => 'ed25519', 'keyBits' => 256, 'testing' => true], array_intersect_key($key, array_flip(['found', 'keyType', 'keyBits', 'testing'])));
        self::assertFalse($missing['found']);

        $reverse = (new HostChecks($dns))->reverse('192.0.2.1');
        self::assertSame('mail.example.com', $reverse['confirmed']);
    }

    public function testRequestIsSanitised(): void
    {
        $request = CheckRequest::from([
            'ip' => '10.0.0.1',
            'mailFrom' => '<bounce+abc@News.Example.com>',
            'fromDomain' => 'example.com',
            'dkim' => [['d' => 'example.com', 's' => 's1'], ['d' => 'example.com', 's' => 'bad selector'], ['d' => 'localhost', 's' => 's2']],
        ]);
        self::assertNotNull($request);
        self::assertNull($request->ip, 'private addresses are not checked');
        self::assertSame('bounce+abc@news.example.com', $request->mailFrom);
        self::assertSame([['d' => 'example.com', 's' => 's1']], $request->dkim);
        self::assertNull(CheckRequest::from('nope'));
    }
}
