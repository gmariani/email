<?php

declare(strict_types=1);

namespace EmailReader\Tests\Unit;

use EmailReader\Rdap\NetworkParser;
use EmailReader\Relays\RelayRequest;
use PHPUnit\Framework\TestCase;

final class NetworkParserTest extends TestCase
{
    public function testFindsOwnerAndNestedAbuseContact(): void
    {
        $data = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/rdap-arin-ses.json'), true);
        $network = NetworkParser::parse($data, 'https://rdap.arin.net/registry/ip/54.240.11.162');

        self::assertSame('ARIN', $network['registry']);
        self::assertSame('AWSEMAIL-Z', $network['name']);
        self::assertSame('Amazon Web Services, Inc.', $network['organization']);
        // Amazon's SES ranges have their own abuse desk, separate from EC2's.
        self::assertSame('email-abuse@amazon.com', $network['abuseEmail']);
        self::assertSame(['54.240.0.0/18'], $network['cidrs']);
    }

    public function testOnlyPublicAddressesAreLookedUp(): void
    {
        $request = RelayRequest::fromJson((string) json_encode(['networks' => ['10.0.0.1', '54.240.11.162', '127.0.0.1', '3.211.244.116', '8.8.8.8', '1.1.1.1', '9.9.9.9']]));

        self::assertNotNull($request);
        self::assertSame(['54.240.11.162', '3.211.244.116', '8.8.8.8', '1.1.1.1'], $request->networks);
        self::assertSame([], $request->ips);
    }
}
