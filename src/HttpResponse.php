<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The two things this library ever reads from a provider response: the
 * status code and the body.
 */
final class HttpResponse
{
    public function __construct(
        public readonly int $status,
        public readonly string $body,
    ) {
    }

    public function ok(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }
}
