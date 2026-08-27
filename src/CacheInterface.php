<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * Where the JWKS is cached between logins. The default is InMemoryCache,
 * which lives and dies with the PHP process -- fine for a long-running
 * worker, and under classic per-request PHP it means each request fetches
 * the JWKS once. Back it with something shared (APCu, Redis, your
 * framework's cache) by implementing these two methods; the stored value is
 * a plain array, so any serializing store works.
 */
interface CacheInterface
{
    /**
     * The stored value, or null when the key is missing or expired.
     */
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds): void;
}
