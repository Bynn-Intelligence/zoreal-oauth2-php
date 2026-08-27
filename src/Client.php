<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * The relying-party client. One instance per registered ZOREAL client;
 * immutable after construction, so build it once at boot and share it.
 *
 *     $zoreal = new Client(
 *         clientId: getenv('ZOREAL_CLIENT_ID'),
 *         auth: ClientAuth::clientSecretBasic(getenv('ZOREAL_CLIENT_SECRET')),
 *     );
 *
 *     $login = $zoreal->authenticate(
 *         code: $body['code'],
 *         codeVerifier: $body['code_verifier'],
 *         nonce: $body['nonce'],
 *     );
 *     $login->sub();        // the pairwise subject: your stable user key
 *     $login->userinfo();   // Tier B claims (email, name, ...), fetched once
 */
final class Client
{
    public const VERSION = '0.1.0';

    public const DEFAULT_ISSUER = 'https://id.zoreal.com';

    /**
     * The provider serves its JWKS with a 10-minute public cache; mirroring
     * it here keeps a busy relying party off the endpoint without holding a
     * rotated-out key longer than the provider itself would.
     */
    public const JWKS_TTL = 600;

    private const JWKS_CACHE_PREFIX = 'zoreal_oauth2_jwks:';

    public readonly string $clientId;

    public readonly string $issuer;

    private readonly ClientAuth $auth;

    private readonly CacheInterface $cache;

    private readonly HttpTransportInterface $transport;

    private readonly JwksFetcherInterface $jwksFetcher;

    /**
     * $auth defaults to ClientAuth::none(), the public-client posture:
     * PKCE alone, Tier A scopes only. A confidential client passes the
     * ClientAuth for the method it registered.
     *
     * $cache holds the JWKS between logins. The default is in-process;
     * hand in a shared store (two methods, see CacheInterface) so a
     * multi-process deployment fetches the key set once rather than once
     * per process.
     *
     * $transport and $jwksFetcher exist to be replaced in tests and exotic
     * deployments; when you inject a transport for a tls_client_auth
     * client, the certificate configuration is yours to carry, because the
     * default CurlTransport is what applies it.
     */
    public function __construct(
        string $clientId,
        string $issuer = self::DEFAULT_ISSUER,
        ?ClientAuth $auth = null,
        ?CacheInterface $cache = null,
        int $timeout = 10,
        ?HttpTransportInterface $transport = null,
        ?JwksFetcherInterface $jwksFetcher = null,
    ) {
        if (trim($clientId) === '') {
            throw new ConfigurationError('clientId is required');
        }
        if (trim($issuer) === '') {
            throw new ConfigurationError('issuer is required');
        }

        $this->clientId = $clientId;
        $this->issuer = rtrim($issuer, '/');
        $this->auth = $auth ?? ClientAuth::none();
        $this->cache = $cache ?? new InMemoryCache();
        $this->transport = $transport ?? new CurlTransport($timeout, $this->auth->tlsCertificate());
        $this->jwksFetcher = $jwksFetcher ?? new HttpJwksFetcher($this->transport);
    }

    /**
     * The whole login, in order: exchange the code (with the PKCE verifier
     * the browser SDK handed over), verify the ID token against the JWKS,
     * check the nonce when the caller has it. Returns a Login; personal data
     * is NOT fetched here, because the ID token never carries it and not
     * every caller wants it -- Login::userinfo() fetches on first use.
     */
    public function authenticate(string $code, string $codeVerifier, ?string $nonce = null): Login
    {
        $tokens = $this->exchange($code, $codeVerifier);
        $idToken = (string) $tokens['id_token'];
        $claims = $this->verifyIdToken($idToken, $nonce);

        $accessToken = $tokens['access_token'] ?? null;
        $scope = $tokens['scope'] ?? null;

        return new Login(
            client: $this,
            claims: $claims,
            idToken: $idToken,
            accessToken: is_string($accessToken) && $accessToken !== '' ? $accessToken : null,
            scope: is_string($scope) ? $scope : null,
        );
    }

    /**
     * POST /token. The verifier is mandatory: PKCE is required for every
     * ZOREAL client, and the browser SDK that generated it hands it to your
     * frontend precisely so your backend can present it here. The client
     * authentication rides along per the registered method -- a Basic
     * header, a fresh private_key_jwt assertion, the mutual-TLS certificate
     * on the connection, or nothing at all for a public client.
     *
     * @return array<string, mixed> the token response: id_token, access_token, token_type, expires_in, scope
     */
    public function exchange(string $code, string $codeVerifier): array
    {
        if (trim($code) === '') {
            throw new \InvalidArgumentException('code is required');
        }
        if (trim($codeVerifier) === '') {
            throw new \InvalidArgumentException('code_verifier is required');
        }

        $tokenEndpoint = $this->issuer . '/token';
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'code_verifier' => $codeVerifier,
            'client_id' => $this->clientId,
        ];
        $form += $this->auth->formFields($this->clientId, $tokenEndpoint);
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ];
        $headers += $this->auth->headers($this->clientId);

        try {
            $response = $this->transport->send('POST', $tokenEndpoint, $headers, http_build_query($form));
        } catch (TransportError $e) {
            throw new ExchangeError('server_error', 'could not reach the token endpoint: ' . $e->getMessage(), null, $e);
        }

        $body = $this->parseJson($response->body);
        if (!$response->ok()) {
            $error = $body['error'] ?? null;
            $description = $body['error_description'] ?? null;

            throw new ExchangeError(
                is_string($error) && $error !== '' ? $error : 'server_error',
                is_string($description) && $description !== '' ? $description : 'the provider answered ' . $response->status,
                $response->status,
            );
        }
        $idToken = $body['id_token'] ?? null;
        if (!is_string($idToken) || trim($idToken) === '') {
            throw new ExchangeError('server_error', 'no id_token in the token response');
        }

        return $body;
    }

    /**
     * ES256 against the provider's JWKS, plus iss (exact string equality
     * with the configured issuer), aud, exp and -- when the caller passes
     * the nonce the SDK generated -- the nonce binding. Returns the claims.
     * There is no RS256 fallback on purpose: ZOREAL signs nothing with RSA,
     * and accepting a second algorithm is how algorithm confusion starts.
     * An unknown kid invalidates the cached JWKS and refetches once, which
     * is how a key rotation is absorbed without a restart.
     *
     * @return array<string, mixed>
     */
    public function verifyIdToken(string $idToken, ?string $nonce = null): array
    {
        $header = $this->decodeHeader($idToken);
        $alg = $header['alg'] ?? null;
        if ($alg !== 'ES256') {
            throw new VerificationError(
                'the ID token is signed with ' . (is_string($alg) && $alg !== '' ? $alg : 'no algorithm')
                . '; the provider signs with ES256 only, and this library refuses anything else'
            );
        }
        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;

        $key = $this->signingKey($kid);

        try {
            $decoded = JWT::decode($idToken, $key);
        } catch (\LogicException | \UnexpectedValueException $e) {
            throw new VerificationError($e->getMessage(), 0, $e);
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) json_encode($decoded), true);

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new VerificationError('the ID token issuer is not the configured issuer');
        }
        $aud = $claims['aud'] ?? null;
        $audienceMatches = is_array($aud) ? in_array($this->clientId, $aud, true) : $aud === $this->clientId;
        if (!$audienceMatches) {
            throw new VerificationError('the ID token audience is not this client');
        }
        if ($nonce !== null && $nonce !== '' && ($claims['nonce'] ?? null) !== $nonce) {
            throw new VerificationError('the ID token nonce is not the one this login started with');
        }

        return $claims;
    }

    /**
     * GET /userinfo with the Bearer access token from the exchange. This is
     * the only place personal claims (email, profile.*) are served, and the
     * access token lives ten minutes, so call it as part of handling the
     * login rather than storing the token for later.
     *
     * @return array<string, mixed>
     */
    public function userinfo(string $accessToken): array
    {
        if (trim($accessToken) === '') {
            throw new \InvalidArgumentException('access_token is required');
        }

        try {
            $response = $this->transport->send('GET', $this->issuer . '/userinfo', [
                'Authorization' => 'Bearer ' . $accessToken,
                'Accept' => 'application/json',
            ]);
        } catch (TransportError $e) {
            throw new UserinfoError('could not reach the userinfo endpoint: ' . $e->getMessage(), 0, $e);
        }

        $body = $this->parseJson($response->body);
        if (!$response->ok()) {
            $description = $body['error_description'] ?? null;

            throw new UserinfoError(
                is_string($description) && $description !== '' ? $description : 'userinfo answered ' . $response->status
            );
        }

        return $body;
    }

    /**
     * The verification key for this token, from the cached JWKS. An unknown
     * kid invalidates and refetches once: the legitimate reason a kid is
     * missing is that the provider rotated keys since the cache was warmed.
     */
    private function signingKey(?string $kid): Key
    {
        $keys = $this->parsedJwks(refresh: false);
        $key = $this->pickKey($keys, $kid);
        if ($key === null) {
            $keys = $this->parsedJwks(refresh: true);
            $key = $this->pickKey($keys, $kid);
        }
        if ($key === null) {
            throw new VerificationError(
                $kid === null
                    ? 'the ID token names no key and the provider JWKS holds more than one'
                    : 'the ID token key is not in the provider JWKS'
            );
        }

        return $key;
    }

    /**
     * @param array<int|string, Key> $keys
     */
    private function pickKey(array $keys, ?string $kid): ?Key
    {
        if ($kid !== null) {
            return $keys[$kid] ?? null;
        }

        return count($keys) === 1 ? reset($keys) : null;
    }

    /**
     * @return array<int|string, Key>
     */
    private function parsedJwks(bool $refresh): array
    {
        $cacheKey = self::JWKS_CACHE_PREFIX . $this->issuer;
        $jwks = $refresh ? null : $this->cache->get($cacheKey);
        if (!is_array($jwks) || !isset($jwks['keys'])) {
            $jwks = $this->jwksFetcher->fetch($this->issuer . '/jwks');
            $this->cache->set($cacheKey, $jwks, self::JWKS_TTL);
        }

        try {
            return JWK::parseKeySet($jwks, 'ES256');
        } catch (\Throwable $e) {
            throw new VerificationError('the provider JWKS could not be parsed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeHeader(string $jwt): array
    {
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            throw new VerificationError('the ID token is not a compact JWT');
        }
        $decoded = base64_decode(strtr($segments[0], '-_', '+/'));
        $header = $decoded === false ? null : json_decode($decoded, true);
        if (!is_array($header)) {
            throw new VerificationError('the ID token header could not be decoded');
        }

        return $header;
    }

    /**
     * @return array<string, mixed>
     */
    private function parseJson(string $body): array
    {
        $parsed = json_decode($body, true);

        return is_array($parsed) ? $parsed : [];
    }
}
