<?php

declare(strict_types=1);

namespace EmailReader\Dns;

/**
 * Where the live checks get DNS answers: Lookup in production, fixed records in tests.
 */
interface DnsSource
{
    /**
     * @param list<array{0:string,1:string}> $questions [name, type]
     * @return list<array{name:string,type:string,status:string,records:list<array<string,mixed>>}>
     */
    public function many(array $questions): array;

    /**
     * @return array{name:string,type:string,status:string,records:list<array<string,mixed>>}
     */
    public function one(string $name, string $type): array;

    /** @return list<string> IPv4 and IPv6 addresses of a host */
    public function addresses(string $host): array;
}
