<?php

declare(strict_types=1);

namespace EmailReader\Checks;

use EmailReader\Dns\DnsSource;

/**
 * Fetches and validates the From domain's DMARC record (RFC 7489): falls back
 * to the organisational domain, checks every tag, and confirms that report
 * addresses on other domains have agreed to receive reports.
 */
final class DmarcCheck
{
    private const POLICIES = ['none', 'quarantine', 'reject'];

    public function __construct(private readonly DnsSource $dns)
    {
    }

    /**
     * @return array<string,mixed>
     */
    public function check(string $domain, string $orgDomain): array
    {
        $found = $this->record($domain);
        $policyDomain = $domain;
        if ($found['records'] === [] && $orgDomain !== $domain && $found['status'] !== 'error') {
            $found = $this->record($orgDomain);
            $policyDomain = $orgDomain;
        }

        $base = ['domain' => $domain, 'policyDomain' => $policyDomain, 'host' => "_dmarc.{$policyDomain}", 'inherited' => $policyDomain !== $domain];
        if ($found['status'] === 'error') {
            return $base + ['found' => false, 'lookupFailed' => true, 'valid' => false, 'record' => null, 'tags' => [], 'errors' => ["DNS error looking up _dmarc.{$policyDomain}; try again in a moment."], 'warnings' => [], 'reports' => []];
        }
        if ($found['records'] === []) {
            return $base + [
                'found' => false,
                'valid' => false,
                'record' => null,
                'tags' => [],
                'errors' => ["No DMARC record at _dmarc.{$domain}" . ($orgDomain !== $domain ? " or _dmarc.{$orgDomain}" : '') . ': anyone can send mail using this domain in From, and receivers have no policy to apply.'],
                'warnings' => [],
                'reports' => [],
            ];
        }

        $record = $found['records'][0];
        $errors = [];
        $warnings = [];
        if (count($found['records']) > 1) {
            $errors[] = 'More than one DMARC record is published; receivers ignore them all.';
        }

        $tags = [];
        foreach (explode(';', $record) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            if (!str_contains($part, '=')) {
                $errors[] = "\"{$part}\" isn't a tag=value pair.";
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $part, 2));
            $tags[strtolower($key)] = $value;
        }

        if (array_key_first($tags) !== 'v' || $tags['v'] !== 'DMARC1') {
            $errors[] = 'The record must start with v=DMARC1.';
        }
        $p = strtolower($tags['p'] ?? '');
        if ($p === '') {
            $errors[] = 'The required p= (policy) tag is missing.';
        } elseif (!in_array($p, self::POLICIES, true)) {
            $errors[] = "p={$tags['p']} isn't a valid policy (none, quarantine or reject).";
        } elseif ($p === 'none') {
            $warnings[] = 'The policy is p=none: receivers only monitor, so mail that fails DMARC is still delivered. The domain isn\'t protected against spoofing until the policy is quarantine or reject.';
        }
        foreach (['sp', 'np'] as $key) {
            if (isset($tags[$key]) && !in_array(strtolower($tags[$key]), self::POLICIES, true)) {
                $errors[] = "{$key}={$tags[$key]} isn't a valid policy.";
            }
        }
        if (isset($tags['sp']) && in_array($p, ['quarantine', 'reject'], true) && strtolower($tags['sp']) === 'none') {
            $warnings[] = 'Subdomains are exempt (sp=none): mail claiming to come from any subdomain isn\'t protected.';
        }
        if (isset($tags['pct'])) {
            if (!ctype_digit($tags['pct']) || (int) $tags['pct'] > 100) {
                $errors[] = "pct={$tags['pct']} must be a number from 0 to 100.";
            } elseif ((int) $tags['pct'] < 100) {
                $warnings[] = "pct={$tags['pct']}: the policy only applies to {$tags['pct']}% of failing mail; the rest is treated as p=none.";
            }
        }
        foreach (['adkim', 'aspf'] as $key) {
            if (isset($tags[$key]) && !in_array(strtolower($tags[$key]), ['r', 's'], true)) {
                $errors[] = "{$key}={$tags[$key]} must be r (relaxed) or s (strict).";
            }
        }
        if (!isset($tags['rua'])) {
            $warnings[] = 'No rua= tag: the domain owner gets no aggregate reports, so they can\'t see who is sending mail as their domain, legitimately or not.';
        }

        $reports = [];
        foreach (['rua', 'ruf'] as $key) {
            foreach (array_filter(array_map('trim', explode(',', $tags[$key] ?? ''))) as $uri) {
                $address = (string) preg_replace('/^mailto:/i', '', preg_replace('/!\d+[kmgt]?$/i', '', $uri));
                if (!preg_match('/^mailto:/i', $uri) || !str_contains($address, '@')) {
                    $errors[] = "{$key}: \"{$uri}\" must be a mailto: address.";
                    continue;
                }
                $reportDomain = strtolower(substr($address, strrpos($address, '@') + 1));
                $external = $reportDomain !== $policyDomain && !str_ends_with($reportDomain, ".{$orgDomain}") && $reportDomain !== $orgDomain;
                $reports[] = ['tag' => $key, 'address' => $address, 'domain' => $reportDomain, 'external' => $external, 'authorized' => $external ? null : true];
            }
        }
        // Reports to another domain need that domain's consent (RFC 7489 §7.1).
        $external = array_filter($reports, fn ($r) => $r['external']);
        if ($external) {
            $answers = $this->dns->many(array_values(array_map(fn ($r) => ["{$policyDomain}._report._dmarc.{$r['domain']}", 'TXT'], $external)));
            foreach (array_keys($external) as $n => $i) {
                $ok = (bool) array_filter(array_column($answers[$n]['records'], 'txt'), fn ($t) => preg_match('/^v=DMARC1/i', trim($t)));
                $reports[$i]['authorized'] = $ok;
                if (!$ok) {
                    $warnings[] = "{$reports[$i]['domain']} hasn't authorised reports for {$policyDomain} (no record at {$policyDomain}._report._dmarc.{$reports[$i]['domain']}), so receivers won't send {$reports[$i]['tag']} reports there.";
                }
            }
        }

        return $base + [
            'found' => true,
            'valid' => !$errors,
            'record' => $record,
            'tags' => $tags,
            'errors' => $errors,
            'warnings' => $warnings,
            'reports' => $reports,
        ];
    }

    /**
     * @return array{status:'ok'|'error',records:list<string>}
     */
    private function record(string $domain): array
    {
        $answer = $this->dns->one("_dmarc.{$domain}", 'TXT');
        if (!in_array($answer['status'], ['NOERROR', 'NXDOMAIN'], true)) {
            return ['status' => 'error', 'records' => []];
        }
        $records = array_values(array_filter(array_map('trim', array_column($answer['records'], 'txt')), fn ($t) => preg_match('/^v=DMARC1/i', $t)));
        return ['status' => 'ok', 'records' => $records];
    }
}
