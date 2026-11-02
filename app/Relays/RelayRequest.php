<?php

declare(strict_types=1);

namespace EmailReader\Relays;

use EmailReader\Support\Ip;

/**
 * What the front-end asks the API to look up: the IP addresses and host names
 * of the servers an email passed through, and the few addresses (where the
 * message really came from) whose network owner and abuse contact it wants.
 * Anything malformed is dropped.
 */
final class RelayRequest
{
    /** More than any real Received chain has. */
    public const MAX_ITEMS = 40;
    /** Registry lookups are slow and sequential: only the addresses that matter. */
    public const MAX_NETWORKS = 4;

    /**
     * @param list<string> $ips
     * @param list<string> $hosts
     * @param list<string> $networks
     */
    public function __construct(public readonly array $ips, public readonly array $hosts, public readonly array $networks = [])
    {
    }

    public static function fromJson(string $json): ?self
    {
        $body = json_decode($json, true);
        if (!is_array($body) || !is_array($body['ips'] ?? []) || !is_array($body['hosts'] ?? []) || !is_array($body['networks'] ?? [])) {
            return null;
        }

        $ips = [];
        foreach ($body['ips'] ?? [] as $ip) {
            $ip = is_string($ip) ? self::normalizeIp($ip) : null;
            if ($ip !== null) {
                $ips[$ip] = true;
            }
        }

        $hosts = [];
        foreach ($body['hosts'] ?? [] as $host) {
            $host = is_string($host) ? self::normalizeHost($host) : null;
            if ($host !== null) {
                $hosts[$host] = true;
            }
        }

        $networks = [];
        foreach ($body['networks'] ?? [] as $ip) {
            $ip = is_string($ip) ? self::normalizeIp($ip) : null;
            if ($ip !== null && Ip::isPublic($ip)) {
                $networks[$ip] = true;
            }
        }

        return new self(
            array_slice(array_keys($ips), 0, self::MAX_ITEMS),
            array_slice(array_keys($hosts), 0, self::MAX_ITEMS),
            array_slice(array_keys($networks), 0, self::MAX_NETWORKS),
        );
    }

    /** "IPv6:2001:db8::1" (address literal) and compressed/expanded forms => canonical form. */
    public static function normalizeIp(string $ip): ?string
    {
        $ip = (string) preg_replace('/^ipv6:/i', '', trim($ip, " []"));
        $bin = @inet_pton($ip);
        return $bin === false ? null : (string) inet_ntop($bin);
    }

    /**
     * A fully-qualified host name worth resolving. Single labels ("localhost",
     * "mail", Exchange server names) can't be resolved from outside anyway.
     */
    public static function normalizeHost(string $host): ?string
    {
        $host = strtolower(rtrim(trim($host), '.'));
        if (strlen($host) > 253 || Ip::isIp($host) || !str_contains($host, '.')) {
            return null;
        }
        foreach (explode('.', $host) as $label) {
            if (!preg_match('/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$/', $label)) {
                return null;
            }
        }
        // Reserved names that never resolve publicly.
        if (preg_match('/\.(local|localdomain|internal|lan|home|corp|invalid|test|example|arpa)$/', $host)) {
            return null;
        }
        return $host;
    }
}
