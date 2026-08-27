<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The default JWKS fetcher: GET {issuer}/jwks over the transport. Every
 * failure is a VerificationError, because a token that cannot be checked
 * against the provider's keys is a token that cannot be accepted.
 */
final class HttpJwksFetcher implements JwksFetcherInterface
{
    public function __construct(private readonly HttpTransportInterface $transport)
    {
    }

    public function fetch(string $url): array
    {
        try {
            $response = $this->transport->send('GET', $url, ['Accept' => 'application/json']);
        } catch (TransportError $e) {
            throw new VerificationError('could not fetch the provider JWKS: ' . $e->getMessage(), 0, $e);
        }
        if (!$response->ok()) {
            throw new VerificationError('could not fetch the provider JWKS (' . $response->status . ')');
        }

        $jwks = json_decode($response->body, true);
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new VerificationError('the provider JWKS response did not contain keys');
        }

        return $jwks;
    }
}
