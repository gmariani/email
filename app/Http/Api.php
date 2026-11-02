<?php

declare(strict_types=1);

namespace EmailReader\Http;

use EmailReader\Checks\AuthChecker;
use EmailReader\Checks\CheckRequest;
use EmailReader\Config;
use EmailReader\Relays\RelayLocator;
use EmailReader\Relays\RelayRequest;
use EmailReader\Support\Cache;

/**
 * POST api.php  {"ips":["…"],"hosts":["…"],"networks":["…"]}  =>  {"ok":true,"data":{…},"meta":{…}}
 * POST api.php  {"checks":{"ip":"…","mailFrom":"…","fromDomain":"…","dkim":[…]}}  =>  live SPF/DKIM/DMARC/DNS checks
 *
 * The email itself is parsed in the browser and never sent here: only the
 * relay addresses and host names found in its Received headers.
 */
final class Api
{
    /** Request bodies are a short JSON list; anything bigger isn't from our page. */
    private const MAX_BODY = 16_384;

    public function __construct(private readonly Config $config)
    {
    }

    public function handle(): never
    {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Robots-Tag: noindex');
        header('Cross-Origin-Resource-Policy: same-origin');

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            header('Allow: POST');
            $this->fail(405, 'Method not allowed.');
        }

        $denied = (new ApiGuard($this->config))->check();
        if ($denied !== null) {
            if (isset($denied[2])) {
                header('Retry-After: ' . $denied[2]);
            }
            $this->fail($denied[0], $denied[1]);
        }

        $body = (string) file_get_contents('php://input', false, null, 0, self::MAX_BODY + 1);
        if (strlen($body) > self::MAX_BODY) {
            $this->fail(413, 'Request too large.');
        }
        // Two kinds of request: live authentication checks, or locating relays.
        $decoded = json_decode($body, true);
        $checks = is_array($decoded) && array_key_exists('checks', $decoded) ? CheckRequest::from($decoded['checks']) : null;
        $request = $checks === null ? RelayRequest::fromJson($body) : null;
        if ($checks === null && $request === null) {
            $this->fail(422, 'Expected {"ips": [...], "hosts": [...], "networks": [...]} or {"checks": {...}}.');
        }

        set_time_limit(30);
        $started = microtime(true);
        $cache = new Cache($this->config->storageDir . '/cache');

        try {
            $data = $checks !== null
                ? (new AuthChecker($this->config, $cache))->check($checks)
                : (new RelayLocator($this->config, $cache))->locate($request);
        } catch (\Throwable $e) {
            error_log(sprintf('[api] %s failed: %s in %s:%d', $checks !== null ? 'checks' : 'relay lookup', $e->getMessage(), $e->getFile(), $e->getLine()));
            $this->fail(500, $this->config->debug ? $e->getMessage() : 'Lookup failed. Please try again.');
        }

        $cache->gc();
        $this->send(200, [
            'ok' => true,
            'data' => $data,
            'meta' => ['elapsedMs' => (int) round((microtime(true) - $started) * 1000)],
        ]);
    }

    private function fail(int $status, string $message): never
    {
        $this->send($status, ['ok' => false, 'error' => $message]);
    }

    /**
     * @param array<string,mixed> $body
     */
    private function send(int $status, array $body): never
    {
        http_response_code($status);
        echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        exit;
    }
}
