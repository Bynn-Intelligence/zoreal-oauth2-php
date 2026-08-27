<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The ID token did not verify: bad signature, wrong issuer or audience,
 * expired, an algorithm other than ES256, or a nonce that was not the one
 * this login started with. Fetching or parsing the provider JWKS failing is
 * also this error, because it leaves the token unverifiable.
 */
class VerificationError extends OAuth2Error
{
}
