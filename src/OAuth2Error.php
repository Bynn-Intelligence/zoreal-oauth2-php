<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The base class every error in this package extends, so a caller can catch
 * the whole family in one clause. No error message in this package ever
 * carries a token, a secret, or a private key.
 */
class OAuth2Error extends \RuntimeException
{
}
