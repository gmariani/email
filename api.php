<?php

declare(strict_types=1);

/*
 * JSON API used by the front-end: locates the relay servers found in an email's
 * headers. See app/Http/Api.php and app/Http/ApiGuard.php.
 */

$config = require __DIR__ . '/app/bootstrap.php';

(new EmailReader\Http\Api($config))->handle();
