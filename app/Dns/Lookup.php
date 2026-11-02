<?php

declare(strict_types=1);

namespace EmailReader\Dns;

use EmailReader\Support\Cache;
use EmailReader\Support\Ip;

/**
 * Plain-array DNS lookups through public recursive resolvers, asked in
 * parallel and cached briefly. Records come back as dns_get_record()-style
 * arrays: ['ip' => …], ['target' => …, 'pri' => …], ['txt' => …].
 */
final class Lookup implements DnsSource
{
    private const FALLBACK_RESOLVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
    private const CACHE_TTL = 300;

    private DnsClient $client;
    /** @var list<string> */
    private array $resolvers;
    public int $queries = 0;

    public function __construct(private readonly Cache $cache, ?string $resolvers = null)
    {
        $this->client = new DnsClient();
        $override = $resolvers
            ? array_values(array_filter(array_map('trim', explode(',', $resolvers)), fn ($ip) => Ip::isIp($ip)))
            : [];
        $this->resolvers = $override ?: self::FALLBACK_RESOLVERS;
    }

    /**
     * @param list<array{0:string,1:string}> $questions [name, type]
     * @return list<array{name:string,type:string,status:string,records:list<array<string,mixed>>}> same order as $questions
     */
    public function many(array $questions): array
    {
        $out = [];
        $missing = [];
        foreach ($questions as $i => [$name, $type]) {
            $name = strtolower(rtrim($name, '.'));
            $cached = $this->cache->get("lookup:{$type}:{$name}");
            if (is_array($cached)) {
                $out[$i] = $cached;
            } else {
                $missing[$i] = [$name, $type];
            }
        }
        if ($missing) {
            $answers = $this->client->query(array_values($missing), $this->resolvers, true);
            // Lost UDP packets and SERVFAILs are common enough to deserve one more round.
            $retry = array_keys(array_filter($answers, fn (DnsAnswer $a) => !$a->isDefinitive()));
            if ($retry) {
                $again = $this->client->query(array_map(fn ($n) => [$answers[$n]->name, $answers[$n]->type], $retry), $this->resolvers, true);
                foreach ($retry as $k => $n) {
                    $answers[$n] = $again[$k];
                }
            }
            $this->queries = $this->client->queries;
            foreach (array_keys($missing) as $n => $i) {
                $answer = $answers[$n];
                $result = [
                    'name' => $answer->name,
                    'type' => $answer->type,
                    'status' => $answer->rcode,
                    'records' => self::records($answer, $answer->type),
                ];
                if ($answer->isDefinitive()) {
                    $this->cache->set("lookup:{$answer->type}:{$answer->name}", $result, self::CACHE_TTL);
                }
                $out[$i] = $result;
            }
        }
        ksort($out);
        return array_values($out);
    }

    /**
     * @return array{name:string,type:string,status:string,records:list<array<string,mixed>>}
     */
    public function one(string $name, string $type): array
    {
        return $this->many([[$name, $type]])[0];
    }

    /** @return list<string> */
    public function txt(string $name): array
    {
        return array_column($this->one($name, 'TXT')['records'], 'txt');
    }

    /**
     * IPv4 and IPv6 addresses of a host.
     *
     * @return list<string>
     */
    public function addresses(string $host): array
    {
        [$a, $aaaa] = $this->many([[$host, 'A'], [$host, 'AAAA']]);
        return array_values(array_unique([...array_column($a['records'], 'ip'), ...array_column($aaaa['records'], 'ip')]));
    }

    /**
     * Only the records of the asked type: a recursive resolver also returns the
     * CNAME chain that led to them.
     *
     * @return list<array<string,mixed>>
     */
    private static function records(DnsAnswer $answer, string $type): array
    {
        $out = [];
        foreach ($answer->answer as $rr) {
            if ($rr->type->label() !== $type) {
                continue;
            }
            $out[] = match ($type) {
                'A', 'AAAA' => ['ip' => (string) $rr->address],
                'MX' => ['pri' => (int) $rr->preference, 'target' => rtrim(strtolower((string) $rr->exchange), '.')],
                'PTR' => ['target' => rtrim(strtolower((string) $rr->ptrdname), '.')],
                'CNAME' => ['target' => rtrim(strtolower((string) $rr->cname), '.')],
                'TXT' => ['txt' => implode('', array_map('strval', $rr->text))],
                default => ['data' => (string) $rr],
            };
        }
        if ($type === 'MX') {
            usort($out, fn ($a, $b) => $a['pri'] <=> $b['pri']);
        }
        return $out;
    }
}
