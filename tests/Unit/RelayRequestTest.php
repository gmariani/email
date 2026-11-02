<?php

declare(strict_types=1);

namespace EmailReader\Tests\Unit;

use EmailReader\Relays\RelayRequest;
use PHPUnit\Framework\TestCase;

final class RelayRequestTest extends TestCase
{
    public function testKeepsValidAddressesAndHosts(): void
    {
        $request = RelayRequest::fromJson((string) json_encode([
            'ips' => ['203.0.113.191', '[54.240.11.162]', 'IPv6:2607:f8b0:4864:20::42f', 'not-an-ip', 42],
            'hosts' => ['Mail.Hosting.Example.NET.', 'spamwall.example.org', 'localhost', 'mail.local', 'bad host', '1.2.3.4'],
        ]));

        self::assertNotNull($request);
        self::assertSame(['203.0.113.191', '54.240.11.162', '2607:f8b0:4864:20::42f'], $request->ips);
        self::assertSame(['mail.hosting.example.net', 'spamwall.example.org'], $request->hosts);
    }

    public function testDeduplicatesAndCaps(): void
    {
        $ips = array_map(fn ($i) => "198.51.100.{$i}", range(1, 60));
        $request = RelayRequest::fromJson((string) json_encode(['ips' => [...$ips, ...$ips]]));

        self::assertNotNull($request);
        self::assertCount(RelayRequest::MAX_ITEMS, $request->ips);
        self::assertSame([], $request->hosts);
    }

    public function testRejectsWrongShapes(): void
    {
        self::assertNull(RelayRequest::fromJson('not json'));
        self::assertNull(RelayRequest::fromJson('"a string"'));
        self::assertNull(RelayRequest::fromJson('{"ips":"1.2.3.4"}'));
    }

    public function testNormalizesIpv6(): void
    {
        self::assertSame('2001:db8::1', RelayRequest::normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001'));
        self::assertNull(RelayRequest::normalizeIp('2001:db8::g'));
    }
}
