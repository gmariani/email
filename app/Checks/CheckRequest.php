<?php

declare(strict_types=1);

namespace EmailReader\Checks;

use EmailReader\Relays\RelayRequest;
use EmailReader\Support\Ip;

/**
 * What the Authentication tab asks the API to check live, from the identities
 * in an email's headers (never the email itself):
 *
 *   {"checks": {"ip": "…", "helo": "…", "mailFrom": "…", "fromDomain": "…",
 *               "orgDomain": "…", "dkim": [{"d": "…", "s": "…"}]}}
 */
final class CheckRequest
{
    public const MAX_SIGNATURES = 5;

    /**
     * @param list<array{d:string,s:string}> $dkim
     */
    public function __construct(
        public readonly ?string $ip,
        public readonly ?string $helo,
        public readonly ?string $mailFrom,
        public readonly ?string $fromDomain,
        public readonly ?string $orgDomain,
        public readonly array $dkim,
    ) {
    }

    /**
     * @param mixed $checks the decoded "checks" object
     */
    public static function from(mixed $checks): ?self
    {
        if (!is_array($checks)) {
            return null;
        }
        $string = fn (string $key): ?string => isset($checks[$key]) && is_string($checks[$key]) && $checks[$key] !== '' ? $checks[$key] : null;

        $ip = $string('ip') !== null ? RelayRequest::normalizeIp((string) $string('ip')) : null;
        if ($ip !== null && !Ip::isPublic($ip)) {
            $ip = null;
        }

        // The envelope sender: an address, or just a domain (null sender "<>" uses the HELO name).
        $mailFrom = null;
        if (($raw = $string('mailFrom')) !== null) {
            $raw = trim($raw, " <>");
            $at = strrpos($raw, '@');
            $domain = RelayRequest::normalizeHost($at === false ? $raw : substr($raw, $at + 1));
            if ($domain !== null && strlen($raw) <= 320) {
                $mailFrom = $at === false ? "postmaster@{$domain}" : substr($raw, 0, $at) . "@{$domain}";
            }
        }

        $dkim = [];
        foreach (is_array($checks['dkim'] ?? null) ? $checks['dkim'] : [] as $sig) {
            $d = is_array($sig) && is_string($sig['d'] ?? null) ? RelayRequest::normalizeHost($sig['d']) : null;
            $s = is_array($sig) && is_string($sig['s'] ?? null) ? strtolower(trim($sig['s'])) : '';
            if ($d !== null && preg_match('/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/', $s) && strlen($s) <= 63) {
                $dkim["{$s}|{$d}"] = ['d' => $d, 's' => $s];
            }
        }

        return new self(
            $ip,
            $string('helo') !== null ? RelayRequest::normalizeHost((string) $string('helo')) : null,
            $mailFrom,
            $string('fromDomain') !== null ? RelayRequest::normalizeHost((string) $string('fromDomain')) : null,
            $string('orgDomain') !== null ? RelayRequest::normalizeHost((string) $string('orgDomain')) : null,
            array_slice(array_values($dkim), 0, self::MAX_SIGNATURES),
        );
    }
}
