<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests\Support;

/**
 * Test key material: fresh P-256 (and RSA) key pairs generated with
 * ext-openssl, plus the JWK form the provider would publish for them.
 */
final class Keys
{
    /**
     * @return array{privatePem: string, publicPem: string, jwk: array<string, string>}
     */
    public static function ec(string $kid): array
    {
        $resource = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        assert($resource !== false);
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);

        return [
            'privatePem' => (string) $privatePem,
            'publicPem' => $details['key'],
            'jwk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'use' => 'sig',
                'alg' => 'ES256',
                'kid' => $kid,
                // openssl strips leading zero bytes from the coordinates;
                // a JWK coordinate is always exactly 32 bytes.
                'x' => self::b64url(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
                'y' => self::b64url(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
            ],
        ];
    }

    /**
     * @return array{privatePem: string, publicPem: string}
     */
    public static function rsa(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        assert($resource !== false);
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);

        return [
            'privatePem' => (string) $privatePem,
            'publicPem' => $details['key'],
        ];
    }

    /**
     * @return array{privatePem: string, publicPem: string}
     */
    public static function p384(): array
    {
        $resource = openssl_pkey_new([
            'curve_name' => 'secp384r1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        assert($resource !== false);
        openssl_pkey_export($resource, $privatePem);
        $details = openssl_pkey_get_details($resource);

        return [
            'privatePem' => (string) $privatePem,
            'publicPem' => $details['key'],
        ];
    }

    /**
     * @param array<string, string> ...$jwks
     *
     * @return array{keys: list<array<string, string>>}
     */
    public static function jwks(array ...$jwks): array
    {
        return ['keys' => array_values($jwks)];
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
