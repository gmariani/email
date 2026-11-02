<?php

declare(strict_types=1);

namespace EmailReader\Checks;

use EmailReader\Dns\DnsSource;
use EmailReader\Support\Ip;

/**
 * The sending server's identity as receivers check it: reverse DNS that
 * confirms forward (FCrDNS), a HELO name that resolves to the server, and
 * whether the sender's domains have mail servers (MX) to receive replies and
 * bounces.
 */
final class HostChecks
{
    public function __construct(private readonly DnsSource $dns)
    {
    }

    /**
     * @return array{ip:string,ptr:list<string>,confirmed:?string,forward:object}
     */
    public function reverse(string $ip): array
    {
        $arpa = Ip::arpa($ip);
        $names = $arpa ? array_slice(array_column($this->dns->one($arpa, 'PTR')['records'], 'target'), 0, 5) : [];
        $forward = [];
        $confirmed = null;
        foreach ($names as $name) {
            $forward[$name] = $this->dns->addresses($name);
            if ($confirmed === null && self::contains($forward[$name], $ip)) {
                $confirmed = $name;
            }
        }
        return ['ip' => $ip, 'ptr' => $names, 'confirmed' => $confirmed, 'forward' => (object) $forward];
    }

    /**
     * @return array{host:string,addresses:list<string>,matchesIp:bool}
     */
    public function helo(string $host, string $ip): array
    {
        $addresses = $this->dns->addresses($host);
        return ['host' => $host, 'addresses' => $addresses, 'matchesIp' => self::contains($addresses, $ip)];
    }

    /**
     * @param list<string> $domains
     * @return array<string,array{mx:list<array{pri:int,target:string,addresses:list<string>}>,addresses:list<string>,nullMx:bool}>
     */
    public function mail(array $domains): array
    {
        $out = [];
        foreach ($domains as $domain) {
            $mx = $this->dns->one($domain, 'MX')['records'];
            $records = [];
            foreach (array_slice($mx, 0, 5) as $record) {
                $records[] = ['pri' => $record['pri'], 'target' => $record['target'], 'addresses' => $record['target'] !== '' ? $this->dns->addresses($record['target']) : []];
            }
            $out[$domain] = [
                'mx' => $records,
                // "0 ." means the domain explicitly accepts no mail (RFC 7505).
                'nullMx' => count($mx) === 1 && $mx[0]['target'] === '',
                'addresses' => $this->dns->addresses($domain),
            ];
        }
        return $out;
    }

    /**
     * @param list<string> $addresses
     */
    private static function contains(array $addresses, string $ip): bool
    {
        $needle = @inet_pton($ip);
        foreach ($addresses as $address) {
            if (@inet_pton($address) === $needle) {
                return true;
            }
        }
        return false;
    }
}
