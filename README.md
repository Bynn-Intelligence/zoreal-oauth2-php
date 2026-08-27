# zoreal/oauth2

Login with ZOREAL for PHP backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR or app link), and hands your frontend an
authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this package does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
zoreal/oauth2 (this package)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react           your frontend: the button, the QR, the polling
```

## Install

```sh
composer require zoreal/oauth2
```

PHP >= 8.1 with ext-curl, ext-json and ext-openssl. One dependency:
`firebase/php-jwt`.

## Quick start

Build one client at boot and share it; it is immutable.

```php
use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\ClientAuth;

$zoreal = new Client(
    clientId: $_ENV['ZOREAL_CLIENT_ID'],                                // ast_...
    auth: ClientAuth::clientSecretBasic($_ENV['ZOREAL_CLIENT_SECRET']),
    issuer: $_ENV['ZOREAL_ISSUER'] ?? Client::DEFAULT_ISSUER,
);
```

The endpoint your frontend posts to:

```php
$login = $zoreal->authenticate(
    code: $body['code'],
    codeVerifier: $body['code_verifier'],   // PKCE is mandatory; the SDK hands it over
    nonce: $body['nonce'],                  // binds the ID token to this login
);

$login->sub();            // "TC5X-JN7G-YTSE-6E63" -- pairwise, stable for YOUR domain
$login->acr();            // "zoreal.live" | "zoreal.device" | "zoreal.session"
$login->assurance();      // uniqueness basis, verification month, chip liveness, trust tier
$login->email();          // from /userinfo, when your client has the email scope
$login->emailVerified();
$login->name();           // from /userinfo, profile.name scope
```

Account matching, the shape that works:

```php
$user = $users->findByProviderUid('zoreal', $login->sub());
if ($user === null) {
    if ($login->emailVerified()) {
        $user = $users->findByEmail($login->email());   // claim, don't collide
    }
    $user ??= $users->create(['email' => $login->email()]);
    $users->linkProvider($user, 'zoreal', $login->sub());
}
```

## What each call does

| Call | What happens |
|---|---|
| `authenticate($code, $codeVerifier, $nonce = null)` | `exchange` + `verifyIdToken`, returns a `Login` |
| `exchange($code, $codeVerifier)` | `POST {issuer}/token` with your registered client authentication |
| `verifyIdToken($jwt, $nonce = null)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `userinfo($accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login::userinfo()` | the above, once, memoized; `[]` when there is no access token |

`Login` reads the ID token claims directly -- `sub()`, `acr()`, `amr()`,
`assurance()`, `ageOver(18)`, `nationality()` -- and the `/userinfo` claims
lazily: `email()`, `emailVerified()`, `name()`, `givenName()`, `familyName()`,
`birthdate()`, `documentType()`, `documentNumber()`, `issuingCountry()`,
`documentExpiresOn()`, `portrait()`.

Errors: `ConfigurationError`, `ExchangeError` (carries the provider's OAuth
error code, reason and HTTP status, verbatim), `VerificationError`,
`UserinfoError` -- all extending `OAuth2Error`. A returning user matched on
`sub` can survive a caught `UserinfoError`; a signup that needs the email
cannot. No error message ever carries a token, a secret or a key.

## Client authentication

Your client registers one `token_endpoint_auth_method` in the dashboard; build
the matching `ClientAuth` here. The provider authenticates against what was
registered, not against what arrives.

```php
use Zoreal\OAuth2\ClientAuth;

ClientAuth::none();                                       // public client: PKCE is the only proof
ClientAuth::clientSecretBasic('zcs_...');                 // the secret travels as HTTP Basic
ClientAuth::privateKeyJwt($pemPrivateKey, kid: 'key-1');  // RFC 7523, signed here per exchange
ClientAuth::tlsClientAuth('/path/client.crt', '/path/client.key');
```

- **`none`** -- no secret, no key; the form carries `client_id` only. A public
  client can only ever have been granted Tier A scopes.
- **`client_secret_basic`** -- the secret rides as the HTTP Basic password,
  never as a form field; the form still carries `client_id` because the
  provider matches the code against it.
- **`private_key_jwt`** -- the library builds and signs a fresh assertion per
  exchange: `iss` = `sub` = your client id, `aud` = the token endpoint,
  `exp` = now + 60 seconds (the provider's maximum), a random single-use
  `jti`. Pass the key as PEM; a P-256 EC key signs ES256 (preferred -- the
  same key type the provider certifies), an RSA key signs RS256, anything
  else is refused at construction. The private key never leaves your process.
- **`tls_client_auth`** -- the certificate and key ride on the connection
  itself, through curl's client-certificate options. The method is
  registrable, and the provider currently answers the exchange with 501; that
  surfaces as an `ExchangeError` with status 501 and the provider's own
  words, because faking a not-yet-served method would be worse than saying
  so. If you inject your own transport, carrying the certificate is its job.

## Things worth knowing before you integrate

- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and -- if registered -- `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `authenticate` alone is not enough for a signup.
- **The access token lives 10 minutes.** Read `/userinfo` while handling the
  login; do not store the token for later.
- **`sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered sector: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration.
- **ES256 only.** The provider signs with nothing else, and this package
  refuses other algorithms -- from the header, before any signature math --
  rather than negotiating.
- **Always pass the nonce through.** The SDK generates it and gives it to your
  frontend in `onSuccess`; without it your backend cannot tell a substituted
  ID token from the real one.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **`portrait` is registrable and not served yet.** The provider does not
  return the claim today; `Login::portrait()` exists so your code does not
  change when it starts to.
- **Sandbox clients accept localhost origins; production clients do not.**
  Registration lives in the ZOREAL dashboard on the asset's OAuth2 tab; Tier B
  scopes (email, profile.\*) need a confidential client on a verified domain.
- **The JWKS is cached for 10 minutes** and refetched once on an unknown
  `kid`, which is how a provider key rotation is absorbed without a restart.
  The default cache is in-process; hand the `Client` anything implementing
  the two-method `CacheInterface` to share it across processes.

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |

## Development against a local provider

Point `issuer:` at your provider instance. The issuer value must match the `iss` inside the
tokens exactly -- it is compared, not normalized.

## License

MIT.
