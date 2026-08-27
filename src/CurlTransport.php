<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The default transport: ext-curl, one handle per request, no redirects
 * followed (every URL this library requests is final), and the mutual-TLS
 * client certificate applied when one is configured -- curl is also where
 * CURLOPT_SSLCERT and CURLOPT_SSLKEY live, which is why tls_client_auth
 * needs no extra dependency.
 */
final class CurlTransport implements HttpTransportInterface
{
    public function __construct(
        private readonly int $timeout = 10,
        private readonly ?TlsClientCertificate $clientCertificate = null,
    ) {
    }

    public function send(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new TransportError('curl could not be initialised');
        }

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $headerLines,
        ]);
        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }
        if ($this->clientCertificate !== null) {
            curl_setopt($handle, CURLOPT_SSLCERT, $this->clientCertificate->certificatePath);
            curl_setopt($handle, CURLOPT_SSLKEY, $this->clientCertificate->privateKeyPath);
            $passphrase = $this->clientCertificate->keyPassphrase();
            if ($passphrase !== null) {
                curl_setopt($handle, CURLOPT_KEYPASSWD, $passphrase);
            }
        }

        // No curl_close: it has been a no-op since PHP 8.0 (the handle is an
        // object, freed with the variable) and is deprecated as of 8.5.
        $responseBody = curl_exec($handle);
        if ($responseBody === false) {
            throw new TransportError('the request could not complete: ' . curl_error($handle));
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        return new HttpResponse($status, (string) $responseBody);
    }
}
