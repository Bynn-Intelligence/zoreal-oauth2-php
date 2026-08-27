<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * One verified login. The ID token claims are already checked when this
 * exists; userinfo is fetched on first use, because the ID token never
 * carries personal data and not every login needs any.
 */
final class Login
{
    /**
     * The verified ID token claims.
     *
     * @var array<string, mixed>
     */
    public readonly array $claims;

    /** The raw compact JWT the claims came from. */
    public readonly string $idToken;

    /** From the token response. The access token lives ten minutes. */
    public readonly ?string $accessToken;

    public readonly ?string $scope;

    /** @var array<string, mixed>|null */
    private ?array $userinfo = null;

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private readonly Client $client,
        array $claims,
        string $idToken,
        ?string $accessToken = null,
        ?string $scope = null,
    ) {
        $this->claims = $claims;
        $this->idToken = $idToken;
        $this->accessToken = $accessToken;
        $this->scope = $scope;
    }

    /**
     * The pairwise subject: stable for your verified domain, meaningless to
     * anyone else. This is the value to key accounts on -- and it is derived
     * from YOUR registered sector, so changing your asset's domain rotates
     * every sub you have stored.
     */
    public function sub(): ?string
    {
        return $this->stringClaim('sub');
    }

    /**
     * How the login was authenticated: zoreal.live, zoreal.device or
     * zoreal.session. Describes what happened, never what was requested.
     */
    public function acr(): ?string
    {
        return $this->stringClaim('acr');
    }

    /**
     * A fresh liveness capture backed this login. The convenience spelling
     * of acr() === 'zoreal.live'; for enforcement, pass $acr to authenticate
     * and let verification refuse the token instead of checking after.
     */
    public function live(): bool
    {
        return $this->acr() === 'zoreal.live';
    }

    /**
     * Equal or stronger satisfies, on the client's ordering
     * (session < device < live). Unknown values satisfy nothing.
     */
    public function satisfiesAcr(string $required): bool
    {
        $actual = $this->acr();
        $actualRank = $actual !== null ? (Client::ACR_ORDER[$actual] ?? null) : null;
        $requiredRank = Client::ACR_ORDER[$required] ?? null;

        return $actualRank !== null && $requiredRank !== null && $actualRank >= $requiredRank;
    }

    /**
     * @return list<string>|null
     */
    public function amr(): ?array
    {
        $amr = $this->claims['amr'] ?? null;

        return is_array($amr) ? array_values($amr) : null;
    }

    /**
     * The assurance block: uniqueness basis, verification month, chip
     * liveness, trust tier, key protection.
     *
     * @return array<string, mixed>|null
     */
    public function assurance(): ?array
    {
        $assurance = $this->claims['zoreal'] ?? null;

        return is_array($assurance) ? $assurance : null;
    }

    /**
     * zoreal.age scope: the registered thresholds arrive as booleans
     * (age_over_18 and so on), never an age. Null when the threshold was not
     * registered for your client, which is a different fact from false.
     */
    public function ageOver(int $threshold): ?bool
    {
        $value = $this->claims['age_over_' . $threshold] ?? null;

        return is_bool($value) ? $value : null;
    }

    /**
     * zoreal.nationality scope: ISO 3166-1 alpha-3, read from the chip.
     */
    public function nationality(): ?string
    {
        return $this->stringClaim('nationality');
    }

    /**
     * The Tier B claims, from /userinfo, fetched once and memoized. Throws
     * UserinfoError when the endpoint refuses -- catch it if your flow can
     * continue without personal data, as a returning user matched on sub
     * can. Returns an empty array when the exchange carried no access token.
     *
     * @return array<string, mixed>
     */
    public function userinfo(): array
    {
        if ($this->userinfo === null) {
            $this->userinfo = $this->accessToken !== null && $this->accessToken !== ''
                ? $this->client->userinfo($this->accessToken)
                : [];
        }

        return $this->userinfo;
    }

    public function email(): ?string
    {
        return $this->userinfoString('email');
    }

    public function emailVerified(): bool
    {
        return ($this->userinfo()['email_verified'] ?? null) === true;
    }

    public function name(): ?string
    {
        return $this->userinfoString('name');
    }

    public function givenName(): ?string
    {
        return $this->userinfoString('given_name');
    }

    public function familyName(): ?string
    {
        return $this->userinfoString('family_name');
    }

    /** ISO 8601, from the profile.birthdate scope. */
    public function birthdate(): ?string
    {
        return $this->userinfoString('birthdate');
    }

    /** profile.document scope, from here down to documentExpiresOn(). */
    public function documentType(): ?string
    {
        return $this->userinfoString('document_type');
    }

    public function documentNumber(): ?string
    {
        return $this->userinfoString('document_number');
    }

    /** ISO 3166-1 alpha-3, the state that issued the document. */
    public function issuingCountry(): ?string
    {
        return $this->userinfoString('issuing_country');
    }

    /** ISO 8601, from the profile.document scope. */
    public function documentExpiresOn(): ?string
    {
        return $this->userinfoString('document_expires_on');
    }

    /**
     * profile.portrait scope. The scope is registrable, and the provider
     * does not serve the portrait claim yet, so this returns null today even
     * with the scope granted; the accessor exists so your code does not
     * change when the provider starts serving it.
     */
    public function portrait(): ?string
    {
        return $this->userinfoString('portrait');
    }

    private function stringClaim(string $name): ?string
    {
        $value = $this->claims[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    private function userinfoString(string $name): ?string
    {
        $value = $this->userinfo()[$name] ?? null;

        return is_string($value) ? $value : null;
    }
}
