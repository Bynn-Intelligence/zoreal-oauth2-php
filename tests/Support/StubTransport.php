<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests\Support;

use Zoreal\OAuth2\HttpResponse;
use Zoreal\OAuth2\HttpTransportInterface;
use Zoreal\OAuth2\TransportError;

/**
 * A transport that serves queued responses and records every request, so a
 * test can assert on exactly what would have gone over the wire.
 */
final class StubTransport implements HttpTransportInterface
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string}> */
    public array $requests = [];

    /** @var list<HttpResponse> */
    private array $queue = [];

    private bool $failNext = false;

    /**
     * @param array<string, mixed>|string $body
     */
    public function queue(int $status, array|string $body): void
    {
        $this->queue[] = new HttpResponse($status, is_string($body) ? $body : (string) json_encode($body));
    }

    public function failNext(): void
    {
        $this->failNext = true;
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'body' => $body,
        ];
        if ($this->failNext) {
            $this->failNext = false;

            throw new TransportError('the request could not complete: stubbed network failure');
        }
        if ($this->queue === []) {
            throw new \LogicException('no response queued for ' . $method . ' ' . $url);
        }

        return array_shift($this->queue);
    }
}
