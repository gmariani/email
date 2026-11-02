<?php

declare(strict_types=1);

namespace EmailReader\Checks;

use EmailReader\Dns\DnsSource;

/**
 * Fetches the public keys DKIM signatures point to (<selector>._domainkey.<domain>).
 * The signature itself is verified in the browser, which has the message body.
 */
final class DkimKeys
{
    public function __construct(private readonly DnsSource $dns)
    {
    }

    /**
     * @param list<array{d:string,s:string}> $signatures
     * @return list<array<string,mixed>>
     */
    public function fetch(array $signatures): array
    {
        $hosts = array_map(fn ($sig) => "{$sig['s']}._domainkey.{$sig['d']}", $signatures);
        $answers = $this->dns->many(array_map(fn ($host) => [$host, 'TXT'], $hosts));
        $out = [];
        foreach ($signatures as $i => $sig) {
            $answer = $answers[$i];
            $base = ['domain' => $sig['d'], 'selector' => $sig['s'], 'host' => $hosts[$i]];
            if (!in_array($answer['status'], ['NOERROR', 'NXDOMAIN'], true)) {
                $out[] = $base + ['found' => false, 'error' => "DNS error ({$answer['status']})."];
                continue;
            }
            $records = array_values(array_filter(array_column($answer['records'], 'txt'), fn ($t) => preg_match('/(^|;)\s*(v=DKIM1|k=|p=)/i', trim($t))));
            if (!$records) {
                $out[] = $base + ['found' => false, 'error' => "No key published at {$hosts[$i]}: it was removed or never existed, so the signature can't be verified."];
                continue;
            }
            $out[] = $base + ['found' => true, 'error' => count($records) > 1 ? 'More than one key record is published here; verifiers may reject it.' : null] + self::parse($records[0]);
        }
        return $out;
    }

    /**
     * A DKIM key record (RFC 6376 §3.6.1): v=DKIM1; k=rsa; p=<base64 key>; t=y …
     *
     * @return array{record:string,tags:array<string,string>,keyType:string,keyBits:?int,publicKey:?string,revoked:bool,testing:bool,strict:bool,weak:bool,hashes:?string}
     */
    public static function parse(string $txt): array
    {
        $tags = [];
        foreach (explode(';', $txt) as $part) {
            if (str_contains($part, '=')) {
                [$key, $value] = explode('=', $part, 2);
                $tags[strtolower(trim($key))] = trim($value);
            }
        }
        $keyType = strtolower($tags['k'] ?? 'rsa');
        $p = (string) preg_replace('/\s+/', '', $tags['p'] ?? '');

        $bits = null;
        if ($p !== '') {
            if ($keyType === 'ed25519') {
                $bits = 256;
            } else {
                $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($p, 64, "\n") . '-----END PUBLIC KEY-----';
                $key = @openssl_pkey_get_public($pem);
                $bits = $key ? (openssl_pkey_get_details($key)['bits'] ?? null) : null;
            }
        }
        $flags = array_map('trim', explode(':', strtolower($tags['t'] ?? '')));

        return [
            'record' => $txt,
            'tags' => $tags,
            'keyType' => $keyType,
            'keyBits' => $bits,
            'publicKey' => $p !== '' ? $p : null,
            'revoked' => $p === '',
            'testing' => in_array('y', $flags, true),
            'strict' => in_array('s', $flags, true),
            'weak' => $bits !== null && $keyType === 'rsa' && $bits < 1024,
            'hashes' => $tags['h'] ?? null,
        ];
    }
}
