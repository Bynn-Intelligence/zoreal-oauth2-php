<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The transport half of tls_client_auth: file paths handed to curl as
 * CURLOPT_SSLCERT and CURLOPT_SSLKEY (plus CURLOPT_KEYPASSWD when the key is
 * encrypted). Paths, not contents, because that is what curl takes; the
 * private key is never read by this library.
 */
final class TlsClientCertificate
{
    public function __construct(
        public readonly string $certificatePath,
        public readonly string $privateKeyPath,
        private readonly ?string $keyPassphrase = null,
    ) {
        if (trim($certificatePath) === '') {
            throw new ConfigurationError('tls_client_auth needs the client certificate path');
        }
        if (trim($privateKeyPath) === '') {
            throw new ConfigurationError('tls_client_auth needs the private key path');
        }
    }

    public function keyPassphrase(): ?string
    {
        return $this->keyPassphrase;
    }

    /**
     * Keep the passphrase out of var_dump and stack traces.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'certificatePath' => $this->certificatePath,
            'privateKeyPath' => $this->privateKeyPath,
        ];
    }
}
