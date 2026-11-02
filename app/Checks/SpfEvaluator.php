<?php

declare(strict_types=1);

namespace EmailReader\Checks;

use EmailReader\Dns\DnsSource;
use EmailReader\Support\Ip;

/**
 * Evaluates SPF the way a receiving server does (RFC 7208 check_host):
 * fetches the domain's record, walks its terms in order, follows include:
 * and redirect=, and records each step so the page can show which term
 * matched the sending IP and why.
 */
final class SpfEvaluator
{
    private const LOOKUP_LIMIT = 10;
    private const VOID_LIMIT = 2;
    private const MX_LIMIT = 10;
    private const DEPTH_LIMIT = 10;

    private int $lookups = 0;
    private int $voidLookups = 0;

    public function __construct(private readonly DnsSource $dns)
    {
    }

    /**
     * @return array{result:string,domain:string,ip:string,lookups:int,lookupLimit:int,voidLookups:int,trace:array<string,mixed>,explanation:?string}
     */
    public function check(string $ip, string $domain, string $sender, ?string $helo): array
    {
        $this->lookups = 0;
        $this->voidLookups = 0;
        $context = ['ip' => $ip, 'sender' => $sender, 'helo' => $helo ?? 'unknown'];
        $trace = $this->checkHost($domain, $context, 0);
        return [
            'result' => $trace['result'],
            'domain' => $domain,
            'ip' => $ip,
            'lookups' => $this->lookups,
            'lookupLimit' => self::LOOKUP_LIMIT,
            'voidLookups' => $this->voidLookups,
            'trace' => $trace,
            'explanation' => $trace['error'] ?? null,
        ];
    }

    /**
     * @param array{ip:string,sender:string,helo:string} $context
     * @return array<string,mixed>
     */
    private function checkHost(string $domain, array $context, int $depth): array
    {
        $node = ['domain' => $domain, 'record' => null, 'terms' => [], 'redirect' => null, 'result' => 'none', 'error' => null];
        if ($depth > self::DEPTH_LIMIT) {
            return ['result' => 'permerror', 'error' => 'Too many nested includes.'] + $node;
        }

        $answer = $this->dns->one($domain, 'TXT');
        if (!in_array($answer['status'], ['NOERROR', 'NXDOMAIN'], true)) {
            return ['result' => 'temperror', 'error' => "DNS error looking up {$domain} ({$answer['status']})."] + $node;
        }
        $records = array_values(array_filter(array_column($answer['records'], 'txt'), fn ($t) => preg_match('/^v=spf1(\s|$)/i', trim($t))));
        if (!$records) {
            return ['result' => 'none', 'error' => "{$domain} has no SPF record."] + $node;
        }
        if (count($records) > 1) {
            return ['result' => 'permerror', 'record' => implode(' | ', $records), 'error' => "{$domain} publishes more than one SPF record."] + $node;
        }
        $node['record'] = trim($records[0]);

        $redirect = null;
        $tokens = preg_split('/\s+/', $node['record']) ?: [];
        array_shift($tokens);
        $terms = [];
        foreach ($tokens as $token) {
            if ($token === '') {
                continue;
            }
            if (preg_match('/^([a-z][a-z0-9_.-]*)=(.*)$/i', $token, $m)) {
                if (strtolower($m[1]) === 'redirect') {
                    $redirect = $m[2];
                }
                $terms[] = ['raw' => $token, 'kind' => 'modifier', 'mechanism' => strtolower($m[1]), 'value' => $m[2]];
                continue;
            }
            $qualifier = match ($token[0]) {
                '-' => 'fail',
                '~' => 'softfail',
                '?' => 'neutral',
                default => 'pass',
            };
            $body = ltrim($token, '+-~?');
            if (!preg_match('#^(all|include|a|mx|ptr|ip4|ip6|exists)(?::([^/]+))?(?:/(\d+))?(?://(\d+))?$#i', $body, $m)) {
                $node['terms'] = [...$terms, ['raw' => $token, 'kind' => 'mechanism', 'matched' => null]];
                return ['result' => 'permerror', 'error' => "Unknown or malformed term \"{$token}\"."] + $node;
            }
            $terms[] = [
                'raw' => $token,
                'kind' => 'mechanism',
                'qualifier' => $qualifier,
                'mechanism' => strtolower($m[1]),
                'value' => ($m[2] ?? '') !== '' ? $m[2] : null,
                'cidr4' => ($m[3] ?? '') !== '' ? (int) $m[3] : null,
                'cidr6' => ($m[4] ?? '') !== '' ? (int) $m[4] : null,
                'matched' => null,
            ];
        }

        foreach ($terms as $i => &$term) {
            if ($term['kind'] !== 'mechanism') {
                continue;
            }
            try {
                $match = $this->mechanism($term, $domain, $context, $depth);
            } catch (SpfError $e) {
                $term['matched'] = null;
                $term['detail'] = $e->getMessage();
                $node['terms'] = $terms;
                return ['result' => $e->result, 'error' => $e->getMessage()] + $node;
            }
            $term['matched'] = $match;
            if ($match) {
                unset($term);
                $node['terms'] = $terms;
                $node['result'] = $terms[$i]['qualifier'];
                return $node;
            }
        }
        unset($term);
        $node['terms'] = $terms;

        if ($redirect !== null) {
            try {
                $target = $this->expand($redirect, $domain, $context);
                $this->countLookup();
            } catch (SpfError $e) {
                return ['result' => $e->result, 'error' => $e->getMessage()] + $node;
            }
            $child = $this->checkHost($target, $context, $depth + 1);
            $node['redirect'] = $child;
            // A redirect to a domain without SPF is a configuration error (RFC 7208 §6.1).
            $node['result'] = $child['result'] === 'none' ? 'permerror' : $child['result'];
            if ($child['result'] === 'none') {
                $node['error'] = "redirect={$target} points to a domain without an SPF record.";
            }
            return $node;
        }

        $node['result'] = 'neutral';
        $node['error'] = 'No term matched, and there is no "all" or redirect: the result is neutral.';
        return $node;
    }

    /**
     * @param array<string,mixed> $term
     * @param array{ip:string,sender:string,helo:string} $context
     */
    private function mechanism(array &$term, string $domain, array $context, int $depth): bool
    {
        $ip = $context['ip'];
        $isV6 = Ip::isV6($ip);
        $target = $term['value'] !== null ? $this->expand($term['value'], $domain, $context) : $domain;
        $cidr = $isV6 ? $term['cidr6'] : $term['cidr4'];

        switch ($term['mechanism']) {
            case 'all':
                $term['detail'] = 'Matches every address.';
                return true;

            case 'ip4':
            case 'ip6':
                $range = $term['value'] . ($term['cidr4'] !== null ? "/{$term['cidr4']}" : '');
                $match = Ip::isIp((string) $term['value']) && Ip::inCidr($ip, $range);
                $term['detail'] = $match ? "{$ip} is in {$range}." : null;
                return $match;

            case 'a':
                $this->countLookup();
                $addresses = $this->addressesOf($target, $isV6);
                $term['detail'] = $addresses ? "{$target} has " . implode(', ', array_slice($addresses, 0, 6)) . (count($addresses) > 6 ? '…' : '') : "{$target} has no address.";
                return $this->anyInRange($ip, $addresses, $cidr);

            case 'mx':
                $this->countLookup();
                $mx = $this->dns->one($target, 'MX');
                $this->checkAnswer($mx, $target);
                $hosts = array_slice(array_column($mx['records'], 'target'), 0, self::MX_LIMIT);
                $all = [];
                foreach ($hosts as $host) {
                    $all = [...$all, ...$this->addressesOf($host, $isV6)];
                }
                $term['detail'] = $hosts ? 'Mail servers: ' . implode(', ', $hosts) : "{$target} has no mail servers.";
                return $this->anyInRange($ip, $all, $cidr);

            case 'ptr':
                $this->countLookup();
                $arpa = Ip::arpa($ip);
                $names = $arpa ? array_column($this->dns->one($arpa, 'PTR')['records'], 'target') : [];
                foreach (array_slice($names, 0, self::MX_LIMIT) as $name) {
                    if (($name === $target || str_ends_with($name, ".{$target}")) && in_array($ip, $this->addressesOf($name, $isV6), true)) {
                        $term['detail'] = "Reverse DNS {$name} is within {$target}. (ptr is deprecated.)";
                        return true;
                    }
                }
                $term['detail'] = 'ptr is deprecated and slow; receivers may ignore it.';
                return false;

            case 'exists':
                $this->countLookup();
                $answer = $this->dns->one($target, 'A');
                $this->checkAnswer($answer, $target);
                $term['detail'] = $answer['records'] ? "{$target} exists." : "{$target} doesn't exist.";
                return (bool) $answer['records'];

            case 'include':
                $this->countLookup();
                $child = $this->checkHost($target, $context, $depth + 1);
                $term['child'] = $child;
                return match ($child['result']) {
                    'pass' => true,
                    'fail', 'softfail', 'neutral' => false,
                    'temperror' => throw new SpfError('temperror', "Temporary DNS error inside include:{$target}."),
                    default => throw new SpfError('permerror', "include:{$target} " . ($child['result'] === 'none' ? 'has no SPF record.' : 'is broken (' . ($child['error'] ?? 'permerror') . ').')),
                };
        }
        return false;
    }

    /** @return list<string> */
    private function addressesOf(string $host, bool $v6): array
    {
        $answer = $this->dns->one($host, $v6 ? 'AAAA' : 'A');
        $this->checkAnswer($answer, $host);
        return array_column($answer['records'], 'ip');
    }

    /**
     * @param list<string> $addresses
     */
    private function anyInRange(string $ip, array $addresses, ?int $cidr): bool
    {
        foreach ($addresses as $address) {
            if ($cidr === null ? inet_pton($address) === inet_pton($ip) : Ip::inCidr($ip, "{$address}/{$cidr}")) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array{status:string,records:list<array<string,mixed>>} $answer
     */
    private function checkAnswer(array $answer, string $name): void
    {
        if (!in_array($answer['status'], ['NOERROR', 'NXDOMAIN'], true)) {
            throw new SpfError('temperror', "DNS error looking up {$name} ({$answer['status']}).");
        }
        // Lookups that return nothing are capped too, to stop abuse (RFC 7208 §4.6.4).
        if (!$answer['records'] && ++$this->voidLookups > self::VOID_LIMIT) {
            throw new SpfError('permerror', 'More than ' . self::VOID_LIMIT . ' lookups returned nothing (void lookup limit).');
        }
    }

    private function countLookup(): void
    {
        if (++$this->lookups > self::LOOKUP_LIMIT) {
            throw new SpfError('permerror', 'The record needs more than ' . self::LOOKUP_LIMIT . ' DNS lookups, so receivers stop with a permanent error.');
        }
    }

    /**
     * Macro expansion (RFC 7208 §7): %{s} sender, %{l} local part, %{o} sender
     * domain, %{d} current domain, %{i} IP, %{h} HELO, %{v} in-addr/ip6, with
     * optional digits (keep the rightmost N parts), "r" (reverse) and delimiters.
     *
     * @param array{ip:string,sender:string,helo:string} $context
     */
    public function expand(string $spec, string $domain, array $context): string
    {
        if (!str_contains($spec, '%')) {
            return strtolower(rtrim($spec, '.'));
        }
        $sender = $context['sender'];
        $at = strrpos($sender, '@');
        $local = $at === false ? 'postmaster' : (substr($sender, 0, $at) ?: 'postmaster');
        $senderDomain = $at === false ? $sender : substr($sender, $at + 1);
        $ip = $context['ip'];
        $dottedIp = Ip::isV6($ip) ? implode('.', str_split(bin2hex((string) inet_pton($ip)))) : $ip;
        $values = [
            's' => $sender, 'l' => $local, 'o' => $senderDomain, 'd' => $domain, 'i' => $dottedIp,
            'p' => 'unknown', 'v' => Ip::isV6($ip) ? 'ip6' : 'in-addr', 'h' => $context['helo'],
        ];

        $out = preg_replace_callback('/%(?:\{([slodipvh])(\d*)(r?)([.\-+,\/_=]*)\}|%|_|-)/i', function (array $m) use ($values): string {
            if ($m[0] === '%%') {
                return '%';
            }
            if ($m[0] === '%_') {
                return ' ';
            }
            if ($m[0] === '%-') {
                return '%20';
            }
            $value = (string) $values[strtolower($m[1])];
            $parts = preg_split('/[' . preg_quote($m[4] !== '' ? $m[4] : '.', '/') . ']/', $value) ?: [$value];
            if (strtolower($m[3]) === 'r') {
                $parts = array_reverse($parts);
            }
            if ($m[2] !== '') {
                $parts = array_slice($parts, -max(1, (int) $m[2]));
            }
            return implode('.', $parts);
        }, $spec);
        if ($out === null || preg_match('/%/', str_replace(['%20'], '', $out))) {
            throw new SpfError('permerror', "Malformed macro in \"{$spec}\".");
        }
        return strtolower(rtrim($out, '.'));
    }
}
