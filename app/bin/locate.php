<?php

declare(strict_types=1);

/*
 * Run the API's relay lookup from the command line, bypassing the token and
 * rate-limit checks. Handy for checking geolocation and DNS on a new server:
 *
 *   php app/bin/locate.php 54.240.11.162 mx.google.com
 *   php app/bin/locate.php 203.0.113.191 --fresh   # ignore cached results
 *   php app/bin/locate.php --network 3.211.244.116  # network owner + abuse contact
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$config = require __DIR__ . '/../bootstrap.php';

use EmailReader\Relays\RelayLocator;
use EmailReader\Relays\RelayRequest;
use EmailReader\Support\Cache;
use EmailReader\Support\Ip;

$args = array_slice($argv, 1);
$fresh = in_array('--fresh', $args, true);
$network = in_array('--network', $args, true);
$args = array_values(array_diff($args, ['--fresh', '--network']));

if (!$args) {
    fwrite(STDERR, "Usage: php app/bin/locate.php <ip or host> [...] [--network] [--fresh]\n");
    exit(1);
}

$ips = array_values(array_filter($args, fn ($arg) => Ip::isIp(trim($arg, '[]'))));
$hosts = array_values(array_diff($args, $ips));
$request = RelayRequest::fromJson((string) json_encode($network ? ['networks' => $ips] : ['ips' => $ips, 'hosts' => $hosts]));

$cacheDir = $fresh ? sys_get_temp_dir() . '/email-analyzer-cli-' . getmypid() : $config->storageDir . '/cache';
$started = microtime(true);
$result = (new RelayLocator($config, new Cache($cacheDir)))->locate($request);

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
fprintf(STDERR, "%d ms\n", (int) round((microtime(true) - $started) * 1000));
