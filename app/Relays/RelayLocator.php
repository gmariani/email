<?php

declare(strict_types=1);

namespace EmailReader\Relays;

use EmailReader\Config;
use EmailReader\Dns\DnsClient;
use EmailReader\Geo\GeoLocator;
use EmailReader\Rdap\NetworkParser;
use EmailReader\Rdap\RdapBootstrap;
use EmailReader\Rdap\RdapClient;
use EmailReader\Support\HttpClient;
use EmailReader\Support\Cache;
use EmailReader\Support\Ip;

/**
 * Locates the servers an email passed through:
 *
 * - host names (the "by" side of a Received header rarely includes an IP)
 *   are resolved to their current IPv4 addresses;
 * - every public address gets its reverse DNS name and an approximate
 *   location + network operator.
 *
 * Private and reserved addresses (10.x, 127.0.0.1, fd00::…) are returned
 * without a location: they only mean something inside the sender's network.
 *
 * Separately, for the addresses the message really came from, it asks the
 * Regional Internet Registry who owns the network and where abuse goes.
 */
final class RelayLocator
{
    private const FALLBACK_RESOLVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
    private const DNS_CACHE_TTL = 3600;

    private DnsClient $dns;
    /** @var list<string> */
    private array $resolvers;

    public function __construct(private readonly Config $config, private readonly Cache $cache)
    {
        $this->dns = new DnsClient();
        $override = $config->dnsResolvers
            ? array_values(array_filter(array_map('trim', explode(',', $config->dnsResolvers)), fn ($ip) => Ip::isIp($ip)))
            : [];
        $this->resolvers = $override ?: self::FALLBACK_RESOLVERS;
    }

    /**
     * @return array{ips:object,hosts:object,geoSource:string,networks:object}
     */
    public function locate(RelayRequest $request): array
    {
        $networks = (object) $this->networks($request->networks);
        if (!$request->ips && !$request->hosts) {
            return ['ips' => (object) [], 'hosts' => (object) [], 'geoSource' => 'none', 'networks' => $networks];
        }

        $hosts = $this->resolve($request->hosts);

        $ips = $request->ips;
        foreach ($hosts as $addresses) {
            array_push($ips, ...$addresses);
        }
        $ips = array_values(array_unique($ips));
        $public = array_values(array_filter($ips, fn ($ip) => Ip::isPublic($ip)));

        $geo = new GeoLocator(
            $this->config->geoCityDb,
            $this->config->geoAsnDb,
            $this->cache,
            $this->config->geoFallbackIpApi,
            $this->config->ipinfoToken,
        );
        $locations = $geo->locateMany($public);
        $names = $this->reverse($public);

        $info = [];
        foreach ($ips as $ip) {
            $info[$ip] = [
                'public' => Ip::isPublic($ip),
                'hostname' => $names[$ip] ?? null,
                'location' => $locations[$ip] ?? null,
            ];
        }

        return [
            'ips' => (object) $info,
            'hosts' => (object) $hosts,
            'geoSource' => $geo->source(),
            'networks' => $networks,
        ];
    }

    /**
     * IP => network owner and abuse contact, from the registry's RDAP record.
     *
     * @param list<string> $ips
     * @return array<string,?array<string,mixed>>
     */
    public function networks(array $ips): array
    {
        if (!$ips) {
            return [];
        }
        $http = new HttpClient($this->config->userAgent);
        $rdap = new RdapClient($http, $this->cache, new RdapBootstrap($http, $this->cache));
        $out = [];
        foreach ($ips as $ip) {
            $result = $rdap->ip($ip);
            $out[$ip] = is_array($result['data']) ? NetworkParser::parse($result['data'], $result['url']) : null;
        }
        return $out;
    }

    /**
     * Host name => its IPv4 addresses (public ones only).
     *
     * @param list<string> $hosts
     * @return array<string,list<string>>
     */
    public function resolve(array $hosts): array
    {
        return $this->cachedLookup('a', $hosts, function (array $missing): array {
            $answers = $this->dns->query(array_map(fn ($host) => [$host, 'A'], $missing), $this->resolvers, true);
            $out = [];
            foreach ($answers as $answer) {
                if (!$answer->isDefinitive()) {
                    continue; // timed out: leave it uncached so the next request tries again
                }
                $addresses = [];
                foreach ($answer->answer as $rr) {
                    if ($rr->type->label() === 'A') {
                        $ip = (string) $rr->address;
                        if (Ip::isPublic($ip)) {
                            $addresses[] = $ip;
                        }
                    }
                }
                $out[$answer->name] = array_values(array_unique($addresses));
            }
            return $out;
        });
    }

    /**
     * IP => PTR host name (null when there is none).
     *
     * @param list<string> $ips
     * @return array<string,?string>
     */
    public function reverse(array $ips): array
    {
        return $this->cachedLookup('ptr', $ips, function (array $missing): array {
            $questions = [];
            foreach ($missing as $ip) {
                $arpa = Ip::arpa($ip);
                if ($arpa !== null) {
                    $questions[$ip] = [$arpa, 'PTR'];
                }
            }
            $answers = $this->dns->query(array_values($questions), $this->resolvers, true);
            $byArpa = [];
            foreach ($answers as $answer) {
                if (!$answer->isDefinitive()) {
                    continue;
                }
                $byArpa[$answer->name] = null;
                foreach ($answer->answer as $rr) {
                    if ($rr->type->label() === 'PTR') {
                        $byArpa[$answer->name] = rtrim(strtolower((string) $rr->ptrdname), '.');
                        break;
                    }
                }
            }
            $out = [];
            foreach ($questions as $ip => [$arpa]) {
                if (array_key_exists($arpa, $byArpa)) {
                    $out[$ip] = $byArpa[$arpa];
                }
            }
            return $out;
        });
    }

    /**
     * Look $keys up in the cache, ask $lookup for the rest in one parallel
     * batch, and cache what it returns.
     *
     * @template T
     * @param list<string> $keys
     * @param callable(list<string>):array<string,T> $lookup
     * @return array<string,T>
     */
    private function cachedLookup(string $kind, array $keys, callable $lookup): array
    {
        $out = [];
        $missing = [];
        foreach ($keys as $key) {
            $cached = $this->cache->get("dns:{$kind}:{$key}");
            if (is_array($cached) && array_key_exists('value', $cached)) {
                $out[$key] = $cached['value'];
            } else {
                $missing[] = $key;
            }
        }
        if ($missing) {
            foreach ($lookup($missing) as $key => $value) {
                $out[$key] = $value;
                $this->cache->set("dns:{$kind}:{$key}", ['value' => $value], self::DNS_CACHE_TTL);
            }
        }
        return $out;
    }
}
