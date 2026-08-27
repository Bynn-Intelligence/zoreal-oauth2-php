<?php

declare(strict_types=1);

namespace Zoreal\OAuth2\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\ConfigurationError;
use Zoreal\OAuth2\Login;
use Zoreal\OAuth2\Tests\Support\Keys;
use Zoreal\OAuth2\Tests\Support\StubJwksFetcher;
use Zoreal\OAuth2\Tests\Support\StubTransport;
use Zoreal\OAuth2\VerificationError;

/**
 * The assurance floor at verification: the acr_values the browser SDK sent
 * on the wire was advisory, the signed acr claim is the proof, and this is
 * the check. Offline, like VerifyTest: the JWKS comes from a stub fetcher.
 */
final class AcrVerifyTest extends TestCase
{
    private const ISSUER = 'https://id.zoreal.example';

    private const CLIENT_ID = 'client-under-test';

    /** @var array{privatePem: string, publicPem: string, jwk: array<string, string>} */
    private array $key;

    private Client $client;

    protected function setUp(): void
    {
        $this->key = Keys::ec('k1');
        $this->client = new Client(
            clientId: self::CLIENT_ID,
            issuer: self::ISSUER,
            transport: new StubTransport(),
            jwksFetcher: new StubJwksFetcher(Keys::jwks($this->key['jwk'])),
        );
    }

    private function token(?string $acr): string
    {
        $claims = [
            'iss' => self::ISSUER,
            'sub' => 's',
            'aud' => self::CLIENT_ID,
            'exp' => time() + 120,
        ];
        if ($acr !== null) {
            $claims['acr'] = $acr;
        }

        return JWT::encode($claims, $this->key['privatePem'], 'ES256', 'k1');
    }

    public function testEqualAcrSatisfies(): void
    {
        $claims = $this->client->verifyIdToken($this->token('zoreal.live'), acr: 'zoreal.live');

        $this->assertSame('zoreal.live', $claims['acr']);
    }

    public function testStrongerAcrSatisfies(): void
    {
        $claims = $this->client->verifyIdToken($this->token('zoreal.live'), acr: 'zoreal.device');

        $this->assertSame('zoreal.live', $claims['acr']);
    }

    public function testWeakerAcrIsRefused(): void
    {
        try {
            $this->client->verifyIdToken($this->token('zoreal.device'), acr: 'zoreal.live');
            $this->fail('a token below the required assurance must be refused');
        } catch (VerificationError $e) {
            // The message names both values, never the token itself.
            $this->assertStringContainsString('zoreal.device', $e->getMessage());
            $this->assertStringContainsString('zoreal.live', $e->getMessage());
        }
    }

    public function testMissingAcrIsRefusedWhenRequired(): void
    {
        $this->expectException(VerificationError::class);
        $this->expectExceptionMessage('zoreal.session');

        $this->client->verifyIdToken($this->token(null), acr: 'zoreal.session');
    }

    public function testUnknownRequiredAcrIsACallerBug(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('unknown required acr zoreal.liveness');

        $this->client->verifyIdToken($this->token('zoreal.live'), acr: 'zoreal.liveness');
    }

    public function testNoRequiredAcrChecksNothing(): void
    {
        $claims = $this->client->verifyIdToken($this->token(null));

        $this->assertSame('s', $claims['sub']);
    }

    public function testLoginConveniences(): void
    {
        $live = new Login(client: $this->client, claims: ['acr' => 'zoreal.live'], idToken: 'x');
        $this->assertTrue($live->live());
        $this->assertTrue($live->satisfiesAcr('zoreal.device'));
        $this->assertFalse($live->satisfiesAcr('made.up'));

        $device = new Login(client: $this->client, claims: ['acr' => 'zoreal.device'], idToken: 'x');
        $this->assertFalse($device->live());
        $this->assertFalse($device->satisfiesAcr('zoreal.live'));
    }
}
