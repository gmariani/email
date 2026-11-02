<?php

declare(strict_types=1);

namespace EmailReader\Checks;

/**
 * Stops SPF evaluation with temperror or permerror (RFC 7208 §2.6.6, §2.6.7).
 */
final class SpfError extends \RuntimeException
{
    public function __construct(public readonly string $result, string $message)
    {
        parent::__construct($message);
    }
}
