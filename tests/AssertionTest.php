<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\ClientAuth;
use Zoreal\OAuth2\ConfigurationError;
use Zoreal\OAuth2\Tests\Support\Keys;
use Zoreal\OAuth2\Tests\Support\StubTransport;

/**
 * The private_key_jwt assertion the library builds, decoded and inspected
 * in the test the way the provider would.
 */
final class AssertionTest extends TestCase
{
    private const ISSUER = 'https://id.zoreal.example';

    private const CLIENT_ID = 'ast_test_client';

    /**
     * @return array{0: StubTransport, 1: Client}
     */
    private function clientWith(ClientAuth $auth): array
    {
        $transport = new StubTransport();
        $client = new Client(
            clientId: self::CLIENT_ID,
            issuer: self::ISSUER,
            auth: $auth,
            transport: $transport,
        );

        return [$transport, $client];
    }

    /**
     * @return array<string, string> the form fields of the recorded token request
     */
    private function exchangeAndParseForm(StubTransport $transport, Client $client): array
    {
        $transport->queue(200, [
            'id_token' => 'opaque-for-this-test',
            'access_token' => 'a',
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'scope' => 'openid',
        ]);
        $client->exchange('code-1', 'verifier-1');

        parse_str((string) end($transport->requests)['body'], $form);

        /** @var array<string, string> $form */
        return $form;
    }

    /**
     * @return array<string, mixed> the assertion's header
     */
    private function header(string $assertion): array
    {
        $segment = explode('.', $assertion)[0];

        return json_decode((string) base64_decode(strtr($segment, '-_', '+/')), true);
    }

    public function testEs256AssertionCarriesTheRightClaims(): void
    {
        $key = Keys::ec('reg-key-1');
        [$transport, $client] = $this->clientWith(ClientAuth::privateKeyJwt($key['privatePem'], 'reg-key-1'));

        $before = time();
        $form = $this->exchangeAndParseForm($transport, $client);
        $after = time();

        $this->assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $form['client_assertion_type']
        );

        // Verifies with the registered public key, ES256.
        $decoded = JWT::decode($form['client_assertion'], new Key($key['publicPem'], 'ES256'));
        $claims = json_decode((string) json_encode($decoded), true);

        $this->assertSame(self::CLIENT_ID, $claims['iss']);
        $this->assertSame(self::CLIENT_ID, $claims['sub']);
        $this->assertSame(self::ISSUER . '/token', $claims['aud']);
        // The provider refuses exp > now + 60; the library signs exactly that ceiling.
        $this->assertLessThanOrEqual($after + 60, $claims['exp']);
        $this->assertGreaterThan($before, $claims['exp']);
        $this->assertGreaterThanOrEqual($before, $claims['iat']);
        $this->assertLessThanOrEqual($after, $claims['iat']);
        $this->assertMatchesRegularExpression('/\A[0-9a-f]{32}\z/', $claims['jti']);

        $header = $this->header($form['client_assertion']);
        $this->assertSame('ES256', $header['alg']);
        $this->assertSame('reg-key-1', $header['kid']);

        // The form still carries the client_id and the PKCE material.
        $this->assertSame(self::CLIENT_ID, $form['client_id']);
        $this->assertSame('code-1', $form['code']);
        $this->assertSame('verifier-1', $form['code_verifier']);
    }

    public function testEachAssertionGetsAFreshJti(): void
    {
        $key = Keys::ec('reg-key-1');
        [$transport, $client] = $this->clientWith(ClientAuth::privateKeyJwt($key['privatePem']));

        $first = $this->exchangeAndParseForm($transport, $client);
        $second = $this->exchangeAndParseForm($transport, $client);

        $jti = fn (string $assertion): string => json_decode(
            (string) base64_decode(strtr(explode('.', $assertion)[1], '-_', '+/')),
            true
        )['jti'];

        $this->assertNotSame($jti($first['client_assertion']), $jti($second['client_assertion']));
    }

    public function testAnRsaKeySignsRs256(): void
    {
        $key = Keys::rsa();
        [$transport, $client] = $this->clientWith(ClientAuth::privateKeyJwt($key['privatePem']));

        $form = $this->exchangeAndParseForm($transport, $client);

        $this->assertSame('RS256', $this->header($form['client_assertion'])['alg']);
        $decoded = JWT::decode($form['client_assertion'], new Key($key['publicPem'], 'RS256'));
        $this->assertSame(self::CLIENT_ID, $decoded->iss);
    }

    public function testTheKidHeaderIsOmittedWhenTheCallerHasNone(): void
    {
        $key = Keys::ec('unused');
        [$transport, $client] = $this->clientWith(ClientAuth::privateKeyJwt($key['privatePem']));

        $form = $this->exchangeAndParseForm($transport, $client);

        $this->assertArrayNotHasKey('kid', $this->header($form['client_assertion']));
    }

    public function testANonP256EcKeyIsRefusedAtConstruction(): void
    {
        $key = Keys::p384();

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('P-256');

        ClientAuth::privateKeyJwt($key['privatePem']);
    }

    public function testAnUnreadableKeyIsRefusedAtConstruction(): void
    {
        $this->expectException(ConfigurationError::class);

        ClientAuth::privateKeyJwt('not a pem at all');
    }
}
