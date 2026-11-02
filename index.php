<?php

declare(strict_types=1);

/*
 * Page shell. The React app parses the pasted or dropped email in the browser;
 * only relay addresses go to api.php, to be located. Server code lives in app/,
 * front-end source in frontend/.
 */

// PHP's built-in dev server (`npm run serve`) uses this file as its router:
// let it serve real files (api.php, build/…) itself.
if (PHP_SAPI === 'cli-server') {
    $file = $_SERVER['DOCUMENT_ROOT'] . rawurldecode((string) strtok((string) $_SERVER['REQUEST_URI'], '?'));
    if (is_file($file) && realpath($file) !== __FILE__) {
        return false;
    }
}

$config = require __DIR__ . '/app/bootstrap.php';

use EmailReader\Http\ApiGuard;
use EmailReader\Http\Vite;

$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/') . '/';

$boot = [
    'token' => (new ApiGuard($config))->issueToken(),
    'base' => $base,
    'api' => $base . 'api.php',
    'mapsKey' => $config->googleMapsKey,
    'inspectorUrl' => $config->domainInspectorUrl,
];

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-Frame-Options: SAMEORIGIN');

$e = static fn (?string $value): string => htmlspecialchars((string) $value, ENT_QUOTES);
$usesDbIp = is_file($config->geoCityDb) && str_contains(basename($config->geoCityDb), 'dbip');
?>
<!doctype html>
<html lang="en" data-bs-theme="dark">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Email Header Analyzer</title>
    <meta name="description" content="Paste an email or drop an .eml/.msg file to see the path it took, whether each hop was encrypted, SPF/DKIM/DMARC results and what every header means.">
    <?php if ($config->googleAnalyticsId) { ?>
        <!-- Google tag (gtag.js) -->
        <script async src="https://www.googletagmanager.com/gtag/js?id=<?= $e($config->googleAnalyticsId) ?>"></script>
        <script>
            window.dataLayer = window.dataLayer || [];

            function gtag() {
                dataLayer.push(arguments);
            }
            gtag('js', new Date());
            gtag('config', <?= json_encode($config->googleAnalyticsId) ?>);
        </script>
    <?php } ?>
    <script>
        window.__EMAIL_ANALYZER__ = <?= json_encode($boot, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES) ?>;
    </script>
    <?= (new Vite($config, $base))->tags() ?>

</head>

<body>
    <div id="root"></div>

    <footer class="bd-footer py-2 py-md-3 mt-5 bg-body-tertiary">
        <div class="container py-2 py-md-3 px-4 px-md-3 text-body-secondary text-center">
            <small class="mb-3 d-block">
                Your email is read entirely in your browser and is never uploaded. Only the IP addresses and host names of the
                servers it passed through are sent to this site, to look up their location and reverse DNS.
            </small>
            <small class="d-block">
                Headers describe what each server <em>said</em> happened. Everything below the first server you trust can be forged by the sender.
            </small>
            <small class="d-block">
                <?php if ($config->ipinfoToken) { ?>IP data powered by <a href="https://ipinfo.io" target="_blank" rel="noopener">IPinfo</a><?= $usesDbIp ? ' and ' : '' ?><?php } ?>
                <?php if ($usesDbIp) { ?><a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a><?php } ?>
            </small>
        </div>
    </footer>
</body>

</html>
