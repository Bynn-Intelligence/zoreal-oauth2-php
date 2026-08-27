<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests;

use PHPUnit\Framework\TestCase;
use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\Login;
use Zoreal\OAuth2\Tests\Support\Keys;
use Zoreal\OAuth2\Tests\Support\StubJwksFetcher;
use Zoreal\OAuth2\Tests\Support\StubTransport;
use Zoreal\OAuth2\UserinfoError;

/**
 * The /userinfo read and the Login accessors that ride on it.
 */
final class UserinfoTest extends TestCase
{
    private const ISSUER = 'https://id.zoreal.example';

    private StubTransport $transport;

    private Client $client;

    protected function setUp(): void
    {
        $this->transport = new StubTransport();
        $this->client = new Client(
            clientId: 'ast_test_client',
            issuer: self::ISSUER,
            transport: $this->transport,
            jwksFetcher: new StubJwksFetcher(Keys::jwks()),
        );
    }

    public function testTheClaimsComeBackAsAnArray(): void
    {
        $this->transport->queue(200, ['sub' => 'S', 'email' => 'holder@example.com', 'email_verified' => true]);

        $claims = $this->client->userinfo('at-1');

        $this->assertSame('holder@example.com', $claims['email']);
        $request = $this->transport->requests[0];
        $this->assertSame('GET', $request['method']);
        $this->assertSame(self::ISSUER . '/userinfo', $request['url']);
        $this->assertSame('Bearer at-1', $request['headers']['Authorization']);
    }

    public function testARefusalCarriesTheProvidersDescriptionAndNeverTheToken(): void
    {
        $this->transport->queue(401, [
            'error' => 'invalid_token',
            'error_description' => 'the access token is not valid',
        ]);

        try {
            $this->client->userinfo('at-secret-value');
            $this->fail('a 401 must throw');
        } catch (UserinfoError $e) {
            $this->assertSame('the access token is not valid', $e->getMessage());
            $this->assertStringNotContainsString('at-secret-value', $e->getMessage());
        }
    }

    public function testARefusalWithoutADescriptionNamesTheStatus(): void
    {
        $this->transport->queue(503, '');

        $this->expectException(UserinfoError::class);
        $this->expectExceptionMessage('userinfo answered 503');

        $this->client->userinfo('at-1');
    }

    public function testLoginFetchesUserinfoLazilyOnceAndMemoizes(): void
    {
        $this->transport->queue(200, [
            'sub' => 'S',
            'email' => 'holder@example.com',
            'email_verified' => true,
            'name' => 'Alva Lindqvist',
            'given_name' => 'Alva',
            'family_name' => 'Lindqvist',
            'birthdate' => '1994-03-12',
            'document_type' => 'passport',
            'document_number' => '59012345',
            'issuing_country' => 'SWE',
            'document_expires_on' => '2031-06-01',
        ]);
        $login = new Login($this->client, ['sub' => 'S'], 'x', 'at-1', 'openid email profile.name');

        // Nothing fetched until a userinfo-backed accessor is read.
        $this->assertCount(0, $this->transport->requests);

        $this->assertSame('holder@example.com', $login->email());
        $this->assertTrue($login->emailVerified());
        $this->assertSame('Alva Lindqvist', $login->name());
        $this->assertSame('Alva', $login->givenName());
        $this->assertSame('Lindqvist', $login->familyName());
        $this->assertSame('1994-03-12', $login->birthdate());
        $this->assertSame('passport', $login->documentType());
        $this->assertSame('59012345', $login->documentNumber());
        $this->assertSame('SWE', $login->issuingCountry());
        $this->assertSame('2031-06-01', $login->documentExpiresOn());
        // Registrable, not served by the provider yet: null, not an error.
        $this->assertNull($login->portrait());

        // Eleven reads, one request.
        $this->assertCount(1, $this->transport->requests);
    }

    public function testLoginWithoutAnAccessTokenNeverTouchesTheWire(): void
    {
        $login = new Login($this->client, ['sub' => 'S'], 'x');

        $this->assertSame([], $login->userinfo());
        $this->assertNull($login->email());
        $this->assertCount(0, $this->transport->requests);
    }

    public function testAnEmptyAccessTokenIsRefusedBeforeTheWire(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->client->userinfo(' ');
    }
}
