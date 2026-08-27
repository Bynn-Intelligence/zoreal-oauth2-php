<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The fallback JWKS cache: one process, TTL respected, no eviction beyond
 * overwrite, because it only ever holds the one key set.
 */
final class InMemoryCache implements CacheInterface
{
    /** @var array<string, array{0: mixed, 1: float}> */
    private array $store = [];

    public function get(string $key): mixed
    {
        if (!isset($this->store[$key])) {
            return null;
        }
        [$value, $expiresAt] = $this->store[$key];
        if ($expiresAt <= microtime(true)) {
            unset($this->store[$key]);

            return null;
        }

        return $value;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->store[$key] = [$value, microtime(true) + $ttlSeconds];
    }
}
