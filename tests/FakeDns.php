<?php

declare(strict_types=1);

namespace EmailReader\Tests;

use EmailReader\Dns\DnsSource;

/**
 * Fixed DNS answers for tests: ['name|TYPE' => list of records] or a status string.
 */
final class FakeDns implements DnsSource
{
    /** @var list<string> */
    public array $asked = [];

    /**
     * @param array<string,list<array<string,mixed>>|string> $zone
     */
    public function __construct(private readonly array $zone)
    {
    }

    public static function txt(string ...$texts): array
    {
        return array_map(fn ($t) => ['txt' => $t], $texts);
    }

    public static function a(string ...$ips): array
    {
        return array_map(fn ($ip) => ['ip' => $ip], $ips);
    }

    public function many(array $questions): array
    {
        return array_map(fn ($q) => $this->one($q[0], $q[1]), $questions);
    }

    public function one(string $name, string $type): array
    {
        $name = strtolower(rtrim($name, '.'));
        $this->asked[] = "{$name}|{$type}";
        $entry = $this->zone["{$name}|{$type}"] ?? null;
        if (is_string($entry)) {
            return ['name' => $name, 'type' => $type, 'status' => $entry, 'records' => []];
        }
        $exists = $entry !== null || (bool) array_filter(array_keys($this->zone), fn ($k) => str_starts_with($k, "{$name}|"));
        return ['name' => $name, 'type' => $type, 'status' => $exists ? 'NOERROR' : 'NXDOMAIN', 'records' => $entry ?? []];
    }

    public function addresses(string $host): array
    {
        return [...array_column($this->one($host, 'A')['records'], 'ip'), ...array_column($this->one($host, 'AAAA')['records'], 'ip')];
    }
}
