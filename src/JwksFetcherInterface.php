<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * Fetches the provider's JWKS. Separate from the transport so a test can
 * hand the client a key set without any HTTP at all; the default,
 * HttpJwksFetcher, is a GET on the transport.
 */
interface JwksFetcherInterface
{
    /**
     * @return array{keys: list<array<string, mixed>>}
     *
     * @throws VerificationError when the JWKS cannot be fetched or is not a key set
     */
    public function fetch(string $url): array;
}
