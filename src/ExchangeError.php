<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The provider refused the code exchange. `$oauthError` is the RFC 6749
 * error code and `$description` the provider's own reason, verbatim: the
 * provider's words are the only signal that says WHY (a consumed code, a
 * PKCE mismatch, a lapsed sector), and rewriting them hides it.
 */
class ExchangeError extends OAuth2Error
{
    public function __construct(
        public readonly string $oauthError,
        public readonly string $description,
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($oauthError . ': ' . $description, 0, $previous);
    }
}
