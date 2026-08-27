<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

use Firebase\JWT\JWT;

/**
 * How the client authenticates the code exchange: the method plus its
 * material, built through the named constructor for the method your client
 * registered. Immutable; the secret and the private key never leave it --
 * not through an accessor, not through var_dump, not in an error message.
 */
final class ClientAuth
{
    private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * The provider rejects assertions with exp > now + 60 (and iat < now - 60),
     * so this library signs the tightest assertion that fits: 60 seconds.
     */
    private const ASSERTION_TTL = 60;

    private function __construct(
        public readonly ClientAuthMethod $method,
        private readonly ?string $clientSecret = null,
        private readonly ?string $privateKeyPem = null,
        private readonly ?string $kid = null,
        private readonly ?string $signingAlgorithm = null,
        private readonly ?TlsClientCertificate $certificate = null,
    ) {
    }

    /**
     * Public client: PKCE is the only proof. The token request carries
     * client_id and nothing else. A public client can only ever have been
     * granted Tier A scopes, so /userinfo has nothing extra to say to it.
     */
    public static function none(): self
    {
        return new self(ClientAuthMethod::None);
    }

    /**
     * Confidential client with a shared secret. The secret travels as HTTP
     * Basic (client_id as user, secret as password); the form still carries
     * client_id because the provider matches the code against it.
     */
    public static function clientSecretBasic(string $clientSecret): self
    {
        if (trim($clientSecret) === '') {
            throw new ConfigurationError('client_secret_basic needs the client secret');
        }

        return new self(ClientAuthMethod::ClientSecretBasic, clientSecret: $clientSecret);
    }

    /**
     * Confidential client with a private key (RFC 7523). Pass the key as PEM;
     * the algorithm is read from the key itself: a P-256 EC key signs ES256
     * (preferred -- it is the same key type the provider certifies), an RSA
     * key signs RS256. Anything else is refused here rather than at the
     * provider. Pass $kid when your registered JWKS names the key, so the
     * provider does not have to try every key you registered.
     */
    public static function privateKeyJwt(string $privateKeyPem, ?string $kid = null): self
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new ConfigurationError('the private key could not be read as a PEM private key');
        }
        $details = openssl_pkey_get_details($key);
        $algorithm = match ($details['type'] ?? null) {
            OPENSSL_KEYTYPE_EC => 'ES256',
            OPENSSL_KEYTYPE_RSA => 'RS256',
            default => throw new ConfigurationError(
                'private_key_jwt needs a P-256 EC key (preferred) or an RSA key'
            ),
        };
        if ($algorithm === 'ES256' && ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new ConfigurationError(
                'the EC private key must be on P-256 (prime256v1); the provider verifies ES256 and nothing else'
            );
        }

        return new self(
            ClientAuthMethod::PrivateKeyJwt,
            privateKeyPem: $privateKeyPem,
            kid: $kid,
            signingAlgorithm: $algorithm,
        );
    }

    /**
     * Mutual-TLS client certificate, carried by curl as CURLOPT_SSLCERT and
     * CURLOPT_SSLKEY. The method is registrable, and the provider currently
     * answers the token exchange with 501 rather than pretending: that
     * response surfaces here as an ExchangeError with status 501 and the
     * provider's own words. Configure it when your registration uses it and
     * the provider announces support; nothing is faked in the meantime.
     */
    public static function tlsClientAuth(
        string $certificatePath,
        string $privateKeyPath,
        ?string $keyPassphrase = null,
    ): self {
        return new self(
            ClientAuthMethod::TlsClientAuth,
            certificate: new TlsClientCertificate($certificatePath, $privateKeyPath, $keyPassphrase),
        );
    }

    /**
     * The headers this method adds to the token request.
     *
     * @return array<string, string>
     */
    public function headers(string $clientId): array
    {
        if ($this->method === ClientAuthMethod::ClientSecretBasic) {
            return ['Authorization' => 'Basic ' . base64_encode($clientId . ':' . $this->clientSecret)];
        }

        return [];
    }

    /**
     * The form fields this method adds to the token request. For
     * private_key_jwt that is a fresh assertion, signed here and now:
     * iss = sub = client_id, aud = the token endpoint, exp = now + 60 (the
     * provider's maximum), iat = now, and a random single-use jti -- the
     * provider refuses a replayed one, so an assertion is never reused.
     *
     * @return array<string, string>
     */
    public function formFields(string $clientId, string $tokenEndpoint): array
    {
        if ($this->method !== ClientAuthMethod::PrivateKeyJwt) {
            return [];
        }

        $now = time();
        $claims = [
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => $tokenEndpoint,
            'exp' => $now + self::ASSERTION_TTL,
            'iat' => $now,
            'jti' => bin2hex(random_bytes(16)),
        ];

        return [
            'client_assertion_type' => self::ASSERTION_TYPE,
            'client_assertion' => JWT::encode(
                $claims,
                (string) $this->privateKeyPem,
                (string) $this->signingAlgorithm,
                $this->kid
            ),
        ];
    }

    /**
     * The certificate configuration for tls_client_auth, for the transport;
     * null for every other method.
     */
    public function tlsCertificate(): ?TlsClientCertificate
    {
        return $this->certificate;
    }

    /**
     * Keep the secret material out of var_dump and stack traces.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['method' => $this->method->value];
    }
}
