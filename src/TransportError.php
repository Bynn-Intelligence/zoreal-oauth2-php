<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The HTTP layer could not complete a request at all: DNS, TCP, TLS, or a
 * timeout. The Client catches this and rethrows it as the domain error of
 * the call that was in flight (ExchangeError, VerificationError or
 * UserinfoError), so callers only ever handle those.
 */
class TransportError extends OAuth2Error
{
}
