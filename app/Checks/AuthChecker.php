<?php

declare(strict_types=1);

namespace EmailReader\Checks;

use EmailReader\Config;
use EmailReader\Dns\Lookup;
use EmailReader\Support\Cache;

/**
 * Runs the live authentication checks for one email: SPF for the sending IP,
 * the DKIM keys its signatures point to, the From domain's DMARC record, and
 * the sending server's DNS identity. Everything reflects DNS as it is now.
 */
final class AuthChecker
{
    public function __construct(private readonly Config $config, private readonly Cache $cache)
    {
    }

    /**
     * @return array<string,mixed>
     */
    public function check(CheckRequest $request): array
    {
        $dns = new Lookup($this->cache, $this->config->dnsResolvers);
        $hosts = new HostChecks($dns);
        $started = microtime(true);

        // SPF checks the envelope sender's domain; with a null sender, the HELO name (RFC 7208 §2.4).
        $spf = null;
        $spfDomain = $request->mailFrom !== null ? substr($request->mailFrom, strrpos($request->mailFrom, '@') + 1) : $request->helo;
        if ($request->ip !== null && $spfDomain !== null) {
            $spf = (new SpfEvaluator($dns))->check($request->ip, $spfDomain, $request->mailFrom ?? "postmaster@{$spfDomain}", $request->helo);
        }

        $dmarc = $request->fromDomain !== null ? (new DmarcCheck($dns))->check($request->fromDomain, $request->orgDomain ?? $request->fromDomain) : null;

        $mailDomains = array_values(array_unique(array_filter([$request->fromDomain, $spfDomain !== $request->helo ? $spfDomain : null])));

        return [
            'spf' => $spf,
            'dkim' => (new DkimKeys($dns))->fetch($request->dkim),
            'dmarc' => $dmarc,
            'reverse' => $request->ip !== null ? $hosts->reverse($request->ip) : null,
            'helo' => $request->helo !== null && $request->ip !== null ? $hosts->helo($request->helo, $request->ip) : null,
            'mail' => (object) $hosts->mail($mailDomains),
            'checkedAt' => gmdate('c'),
            'elapsedMs' => (int) round((microtime(true) - $started) * 1000),
        ];
    }
}
