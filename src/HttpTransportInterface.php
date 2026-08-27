<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The HTTP layer, small enough to double in a test. The default is
 * CurlTransport; inject your own to route through a proxy, to add
 * observability, or to stub the provider offline.
 */
interface HttpTransportInterface
{
    /**
     * @param array<string, string> $headers
     *
     * @throws TransportError when the request could not complete at all
     */
    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse;
}
