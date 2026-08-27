<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\Login;
use Zoreal\OAuth2\Tests\Support\Keys;
use Zoreal\OAuth2\Tests\Support\StubJwksFetcher;
use Zoreal\OAuth2\Tests\Support\StubTransport;
use Zoreal\OAuth2\VerificationError;

/**
 * Offline verification tests: the JWKS is served by a stub fetcher, so
 * nothing here touches the network.
 */
final class VerifyTest extends TestCase
{
    private const ISSUER = 'https://id.zoreal.example';

    private const CLIENT_ID = 'ast_test_client';

    /** @var array{privatePem: string, publicPem: string, jwk: array<string, string>} */
    private array $key;

    private StubJwksFetcher $fetcher;

    private Client $client;

    protected function setUp(): void
    {
        $this->key = Keys::ec('k1');
        $this->fetcher = new StubJwksFetcher(Keys::jwks($this->key['jwk']));
        $this->client = new Client(
            clientId: self::CLIENT_ID,
            issuer: self::ISSUER,
            transport: new StubTransport(),
            jwksFetcher: $this->fetcher,
        );
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function baseClaims(array $overrides = []): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'sub' => '7QK3-9F2M-XR84-B5NP',
            'aud' => self::CLIENT_ID,
            'exp' => time() + 120,
            'iat' => time(),
            'nonce' => 'n-1',
            'acr' => 'zoreal.device',
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function sign(array $claims, ?string $privatePem = null, string $kid = 'k1'): string
    {
        return JWT::encode($claims, $privatePem ?? $this->key['privatePem'], 'ES256', $kid);
    }

    public function testValidTokenVerifiesAndReturnsClaims(): void
    {
        $claims = $this->client->verifyIdToken($this->sign($this->baseClaims()), 'n-1');

        $this->assertSame('7QK3-9F2M-XR84-B5NP', $claims['sub']);
        $this->assertSame('zoreal.device', $claims['acr']);
    }

    public function testNonceMismatchIsRefused(): void
    {
        $this->expectException(VerificationError::class);
        $this->expectExceptionMessage('nonce');

        $this->client->verifyIdToken($this->sign($this->baseClaims()), 'other');
    }

    public function testNonceIsNotCheckedWhenCallerHasNone(): void
    {
        $claims = $this->client->verifyIdToken($this->sign($this->baseClaims()));

        $this->assertSame('7QK3-9F2M-XR84-B5NP', $claims['sub']);
    }

    public function testWrongAudienceIsRefused(): void
    {
        $this->expectException(VerificationError::class);
        $this->expectExceptionMessage('audience');

        $this->client->verifyIdToken($this->sign($this->baseClaims(['aud' => 'ast_other'])));
    }

    public function testWrongIssuerIsRefused(): void
    {
        $this->expectException(VerificationError::class);
        $this->expectExceptionMessage('issuer');

        $this->client->verifyIdToken($this->sign($this->baseClaims(['iss' => 'https://evil.example'])));
    }

    public function testExpiredTokenIsRefused(): void
    {
        $this->expectException(VerificationError::class);

        $this->client->verifyIdToken($this->sign($this->baseClaims(['exp' => time() - 5])));
    }

    public function testForeignKeyIsRefused(): void
    {
        $foreign = Keys::ec('k1');
        $token = $this->sign($this->baseClaims(), $foreign['privatePem']);

        $this->expectException(VerificationError::class);

        $this->client->verifyIdToken($token);
    }

    public function testNonEs256AlgorithmIsRefusedBeforeSignatureChecking(): void
    {
        $token = JWT::encode($this->baseClaims(), str_repeat('a-shared-secret!', 2), 'HS256', 'k1');

        try {
            $this->client->verifyIdToken($token);
            $this->fail('an HS256 token must be refused');
        } catch (VerificationError $e) {
            $this->assertStringContainsString('ES256', $e->getMessage());
        }
        // Refused from the header alone: the JWKS was never even consulted.
        $this->assertSame(0, $this->fetcher->calls);
    }

    public function testRs256IsRefusedEvenWithAValidRsaSignature(): void
    {
        $rsa = Keys::rsa();
        $token = JWT::encode($this->baseClaims(), $rsa['privatePem'], 'RS256', 'k1');

        $this->expectException(VerificationError::class);
        $this->expectExceptionMessage('ES256');

        $this->client->verifyIdToken($token);
    }

    public function testUnknownKidInvalidatesTheCacheAndRefetchesOnce(): void
    {
        $rotated = Keys::ec('k2');
        $fetcher = new StubJwksFetcher(
            Keys::jwks($this->key['jwk']),                    // the stale set
            Keys::jwks($this->key['jwk'], $rotated['jwk']),   // after rotation
        );
        $client = new Client(
            clientId: self::CLIENT_ID,
            issuer: self::ISSUER,
            transport: new StubTransport(),
            jwksFetcher: $fetcher,
        );

        $token = JWT::encode($this->baseClaims(), $rotated['privatePem'], 'ES256', 'k2');
        $claims = $client->verifyIdToken($token, 'n-1');

        $this->assertSame('7QK3-9F2M-XR84-B5NP', $claims['sub']);
        $this->assertSame(2, $fetcher->calls);
    }

    public function testAKidStillUnknownAfterTheRefetchIsRefused(): void
    {
        $stranger = Keys::ec('k9');
        $token = JWT::encode($this->baseClaims(), $stranger['privatePem'], 'ES256', 'k9');

        try {
            $this->client->verifyIdToken($token);
            $this->fail('a kid absent from the JWKS must be refused');
        } catch (VerificationError $e) {
            $this->assertStringContainsString('not in the provider JWKS', $e->getMessage());
        }
        $this->assertSame(2, $this->fetcher->calls);
    }

    public function testTheJwksIsCachedBetweenVerifications(): void
    {
        $this->client->verifyIdToken($this->sign($this->baseClaims()));
        $this->client->verifyIdToken($this->sign($this->baseClaims()));

        $this->assertSame(1, $this->fetcher->calls);
    }

    public function testGarbageIsRefused(): void
    {
        $this->expectException(VerificationError::class);

        $this->client->verifyIdToken('not-a-jwt');
    }

    public function testLoginConveniencesReadTheClaims(): void
    {
        $login = new Login(
            client: $this->client,
            claims: $this->baseClaims([
                'age_over_18' => true,
                'nationality' => 'SWE',
                'amr' => ['hwk', 'face', 'user'],
                'zoreal' => ['trust_tier' => 'high'],
            ]),
            idToken: 'x',
        );

        $this->assertSame('7QK3-9F2M-XR84-B5NP', $login->sub());
        $this->assertSame('zoreal.device', $login->acr());
        $this->assertSame(['hwk', 'face', 'user'], $login->amr());
        $this->assertTrue($login->ageOver(18));
        $this->assertNull($login->ageOver(21));
        $this->assertSame('SWE', $login->nationality());
        $this->assertSame('high', $login->assurance()['trust_tier']);
        // No access token: userinfo is an empty array, never a fetch.
        $this->assertSame([], $login->userinfo());
        $this->assertNull($login->email());
        $this->assertFalse($login->emailVerified());
        $this->assertNull($login->portrait());
    }
}
