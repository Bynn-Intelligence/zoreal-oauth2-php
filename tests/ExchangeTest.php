<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\ClientAuth;
use Zoreal\OAuth2\ExchangeError;
use Zoreal\OAuth2\Tests\Support\Keys;
use Zoreal\OAuth2\Tests\Support\StubJwksFetcher;
use Zoreal\OAuth2\Tests\Support\StubTransport;

/**
 * The code exchange: what goes over the wire for each client authentication
 * method, and how the provider's refusals are surfaced.
 */
final class ExchangeTest extends TestCase
{
    private const ISSUER = 'https://id.zoreal.example';

    private const CLIENT_ID = 'ast_test_client';

    private StubTransport $transport;

    protected function setUp(): void
    {
        $this->transport = new StubTransport();
    }

    private function client(?ClientAuth $auth = null, ?StubJwksFetcher $fetcher = null): Client
    {
        return new Client(
            clientId: self::CLIENT_ID,
            issuer: self::ISSUER,
            auth: $auth,
            transport: $this->transport,
            jwksFetcher: $fetcher ?? new StubJwksFetcher(Keys::jwks()),
        );
    }

    public function testAProviderRefusalSurfacesVerbatim(): void
    {
        $this->transport->queue(400, [
            'error' => 'invalid_grant',
            'error_description' => 'the code is not valid',
        ]);

        try {
            $this->client()->exchange('code-1', 'verifier-1');
            $this->fail('a refused exchange must throw');
        } catch (ExchangeError $e) {
            $this->assertSame('invalid_grant', $e->oauthError);
            $this->assertSame('the code is not valid', $e->description);
            $this->assertSame(400, $e->status);
            $this->assertSame('invalid_grant: the code is not valid', $e->getMessage());
        }
    }

    public function testANonJsonErrorBodyStillMapsToAnExchangeError(): void
    {
        $this->transport->queue(500, 'Bad Gateway');

        try {
            $this->client()->exchange('code-1', 'verifier-1');
            $this->fail('a 500 must throw');
        } catch (ExchangeError $e) {
            $this->assertSame('server_error', $e->oauthError);
            $this->assertSame('the provider answered 500', $e->description);
            $this->assertSame(500, $e->status);
        }
    }

    public function testASuccessWithoutAnIdTokenIsRefused(): void
    {
        $this->transport->queue(200, ['access_token' => 'a', 'token_type' => 'Bearer']);

        $this->expectException(ExchangeError::class);
        $this->expectExceptionMessage('no id_token in the token response');

        $this->client()->exchange('code-1', 'verifier-1');
    }

    public function testANetworkFailureMapsToAnExchangeError(): void
    {
        $this->transport->failNext();

        try {
            $this->client()->exchange('code-1', 'verifier-1');
            $this->fail('a network failure must throw');
        } catch (ExchangeError $e) {
            $this->assertSame('server_error', $e->oauthError);
            $this->assertNull($e->status);
        }
    }

    public function testAPublicClientSendsNoAuthorizationHeaderAndNoAssertion(): void
    {
        $this->transport->queue(200, ['id_token' => 'x']);

        $this->client()->exchange('code-1', 'verifier-1');

        $request = $this->transport->requests[0];
        $this->assertArrayNotHasKey('Authorization', $request['headers']);
        parse_str((string) $request['body'], $form);
        $this->assertSame([
            'grant_type' => 'authorization_code',
            'code' => 'code-1',
            'code_verifier' => 'verifier-1',
            'client_id' => self::CLIENT_ID,
        ], $form);
    }

    public function testClientSecretBasicTravelsAsTheBasicHeaderNeverTheForm(): void
    {
        $this->transport->queue(200, ['id_token' => 'x']);

        $this->client(ClientAuth::clientSecretBasic('zcs_secret'))->exchange('code-1', 'verifier-1');

        $request = $this->transport->requests[0];
        $this->assertSame(
            'Basic ' . base64_encode(self::CLIENT_ID . ':zcs_secret'),
            $request['headers']['Authorization']
        );
        parse_str((string) $request['body'], $form);
        // The form still carries client_id (the provider matches the code
        // against it) and never the secret.
        $this->assertSame(self::CLIENT_ID, $form['client_id']);
        $this->assertArrayNotHasKey('client_secret', $form);
    }

    public function testTheTokenEndpointAndContentTypeAreRight(): void
    {
        $this->transport->queue(200, ['id_token' => 'x']);

        $this->client()->exchange('code-1', 'verifier-1');

        $request = $this->transport->requests[0];
        $this->assertSame('POST', $request['method']);
        $this->assertSame(self::ISSUER . '/token', $request['url']);
        $this->assertSame('application/x-www-form-urlencoded', $request['headers']['Content-Type']);
    }

    public function testTlsClientAuthSurfacesTheProviders501AsTheExchangeErrorItIs(): void
    {
        $this->transport->queue(501, [
            'error' => 'invalid_request',
            'error_description' => 'tls_client_auth is not implemented at this endpoint yet; '
                . 'use private_key_jwt or client_secret_basic',
        ]);
        $auth = ClientAuth::tlsClientAuth('/etc/ssl/client.crt', '/etc/ssl/client.key');

        try {
            $this->client($auth)->exchange('code-1', 'verifier-1');
            $this->fail('the 501 must surface');
        } catch (ExchangeError $e) {
            $this->assertSame(501, $e->status);
            $this->assertSame('invalid_request', $e->oauthError);
            $this->assertStringContainsString('not implemented', $e->description);
        }
        // Transport-level auth adds nothing to the form.
        parse_str((string) $this->transport->requests[0]['body'], $form);
        $this->assertArrayNotHasKey('client_assertion', $form);
    }

    public function testAnEmptyCodeIsRefusedBeforeTheWire(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->client()->exchange('', 'verifier-1');
    }

    public function testAuthenticateExchangesVerifiesAndBuildsTheLogin(): void
    {
        $key = Keys::ec('k1');
        $idToken = JWT::encode([
            'iss' => self::ISSUER,
            'sub' => '7QK3-9F2M-XR84-B5NP',
            'aud' => self::CLIENT_ID,
            'exp' => time() + 120,
            'iat' => time(),
            'nonce' => 'n-1',
            'acr' => 'zoreal.live',
        ], $key['privatePem'], 'ES256', 'k1');
        $this->transport->queue(200, [
            'id_token' => $idToken,
            'access_token' => 'at-1',
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'scope' => 'openid email',
        ]);
        $client = $this->client(fetcher: new StubJwksFetcher(Keys::jwks($key['jwk'])));

        $login = $client->authenticate('code-1', 'verifier-1', 'n-1');

        $this->assertSame('7QK3-9F2M-XR84-B5NP', $login->sub());
        $this->assertSame('zoreal.live', $login->acr());
        $this->assertSame('at-1', $login->accessToken);
        $this->assertSame('openid email', $login->scope);
        $this->assertSame($idToken, $login->idToken);
        // authenticate() does not touch /userinfo: one request, the exchange.
        $this->assertCount(1, $this->transport->requests);
    }
}
