<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests\Support;

use Zoreal\OAuth2\JwksFetcherInterface;

/**
 * A JWKS fetcher that serves canned key sets and counts its calls. When
 * several responses are queued, each fetch consumes one; the last response
 * keeps answering, so a cache-behaviour test can count fetches without
 * running out.
 */
final class StubJwksFetcher implements JwksFetcherInterface
{
    public int $calls = 0;

    /** @var list<array{keys: list<array<string, mixed>>}> */
    private array $responses;

    /**
     * @param array{keys: list<array<string, mixed>>} ...$responses
     */
    public function __construct(array ...$responses)
    {
        $this->responses = array_values($responses);
    }

    public function fetch(string $url): array
    {
        $this->calls++;
        if ($this->responses === []) {
            throw new \LogicException('no JWKS queued in the stub');
        }

        return count($this->responses) > 1 ? array_shift($this->responses) : $this->responses[0];
    }
}
