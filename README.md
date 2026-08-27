# zoreal/oauth2

[![Packagist Version](https://img.shields.io/packagist/v/zoreal/oauth2)](https://packagist.org/packages/zoreal/oauth2) [![PHP Version](https://img.shields.io/packagist/php-v/zoreal/oauth2)](https://packagist.org/packages/zoreal/oauth2) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-oauth2-php/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-oauth2-php/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Bynn-Intelligence/zoreal-oauth2-php/badge)](https://scorecard.dev/viewer/?uri=github.com/Bynn-Intelligence/zoreal-oauth2-php) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

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

## Getting your credentials

Everything the `Client` constructor needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset** -- a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users log in to; its token is
   your `client_id` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and register:
   - the **redirect URIs** and **JavaScript origins** your app uses (requests
     from anything not registered are rejected -- this is the core control),
   - the **scopes** the client is allowed to request (see the catalogue
     below); a request for a scope you did not register is refused,
   - your **client authentication**: generate a **client secret** for
     `client_secret_basic`, or register a **JWKS** for `private_key_jwt`. A
     public client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown
   in the dashboard) before it can request personal-data scopes or sign users
   in; the verified domain is what your users' pairwise `sub` is derived
   against.

The `client_id` is public -- it ships in your frontend. The client secret is a
server-side secret: keep it in your secret store and never put it in the
browser.

### There is no test-identity sandbox -- and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** -- enrol in the
ZOREAL ID app and sign in with it. While building, mark your asset's
environment **sandbox** in the dashboard: a sandbox asset may register
`http://localhost` origins and redirect URIs that a production asset may not.
Flip it to production when you ship. The identities are real either way; only
the allowed origins differ. There is no mock provider and no hosted test
issuer to point at.

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

## Assurance levels -- `acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim -- *Authentication Context Class
Reference*. It is a single string in the ID token that says **how strongly this
particular login was authenticated**. Every ZOREAL login carries one, and it is
the difference between "someone who once enrolled this identity is behind this
request" and "a live human, verified to be the right one, is behind this request
right now".

It answers a question `sub` cannot. `sub()` tells you *who* -- a stable,
pairwise identifier for this person at your site. `acr()` tells you *how sure
ZOREAL is that the person is really there for this login*. A stolen, unlocked
phone can still produce a `sub`; it cannot produce a fresh `zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested -- a login that could only reach a weaker level says so honestly
rather than claiming the level you asked for.

| `acr` | What the holder did | `amr` | What it proves | What it does **not** prove |
|---|---|---|---|---|
| `zoreal.session` | Nothing -- a returning holder at a site they have used before, resumed silently from an existing ZOREAL session, no phone interaction | `[]` | Continuity: the same session ZOREAL already knew | That the holder is present, or even awake |
| `zoreal.device` | Approved the login on their enrolled phone: a signature from a key in the phone's secure element, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a live face was captured for *this* login -- an unlocked phone in the wrong hands still signs |
| `zoreal.live` | All of the above **plus** a fresh face capture this login: a flash-plus-zoom video scored for presentation attacks and screen replay (moire), matched 1:1 against the government document read at enrolment | `["hwk","face","user"]` | A live, real, unique human, verified to be the enrolled person, **at the moment of this login** | -- (this is the strongest level) |

`amr()` (*Authentication Methods References*) is the companion claim listing the
factors used: `hwk` a hardware key, `user` a user-presence/unlock gesture,
`face` a face biometric. `zoreal.live` is exactly `zoreal.device` with `face`
added, because a live login is a device approval with a capture on top.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks
for nothing still requires the enrolled phone and a local unlock. Silence has to
be explicitly asked for (the SDK's `prompt: 'none'` path), and it succeeds only
for a returning holder at a site whose consent they have already given.

### When to require which

- **`zoreal.session`** -- you never *require* this; it is what a returning
  holder gets for a low-stakes convenience re-auth when they ask for the silent
  path.
- **`zoreal.device`** (the default) -- a forum, a community, a normal account
  login. Possession of the enrolled phone plus a local unlock is a high bar
  already; most sites want exactly this and should pass no `acr` at all.
- **`zoreal.live`** -- a bank onboarding, a high-value transaction, an age-gated
  purchase, a first login, a "confirm it is really you" step before a sensitive
  action. Anywhere a *fresh, unforgeable proof of the live, right human* is worth
  the few seconds a face capture costs.

### Requesting versus verifying -- the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the
second is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: 'zoreal.live'`. This is what makes the holder's ZOREAL ID app
   run the face capture before it will approve. It is **advisory** -- it shapes
   what the holder is asked to do, nothing more. A browser is
   attacker-controlled; a value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing `acr`. The signed `acr`
   claim in the ID token -- minted by ZOREAL, not by the browser -- is the proof.

```php
$login = $zoreal->authenticate(
    code: $body['code'],
    codeVerifier: $body['code_verifier'],
    nonce: $body['nonce'],
    acr: 'zoreal.live',   // throws VerificationError unless the signed token says so
);

$login->acr();                          // "zoreal.live" -- what actually happened
$login->live();                         // convenience: acr() === 'zoreal.live'
$login->satisfiesAcr('zoreal.device');  // true (live is stronger than device)
```

**An RP that requests `zoreal.live` on the wire but never passes `acr` here has
checked nothing** -- it has only asked the holder nicely and then trusted a
value it never validated.

### How the check behaves

Verification satisfies **upward**: `zoreal.session < zoreal.device <
zoreal.live`, so a requirement of `zoreal.device` accepts a `zoreal.live` token
(the holder gave you *more* assurance than you demanded). A token whose `acr` is
below the requirement, missing entirely, or outside the vocabulary is refused
with `VerificationError`. An unknown *required* value -- a typo like
`'zoreal.liveness'` -- throws `ConfigurationError` instead, because that is a bug
in your code, not a bad token, and failing every login silently is worse than
saying so.

If you prefer to branch rather than throw, omit `acr` and inspect the result:

```php
$login = $zoreal->authenticate(
    code: $body['code'],
    codeVerifier: $body['code_verifier'],
    nonce: $body['nonce'],
);
if (!$login->satisfiesAcr('zoreal.live')) {
    // step the user up, or refuse the sensitive action
}
```

`satisfiesAcr()` runs the same ordering as the enforcing check, so it agrees
with what `acr: 'zoreal.live'` would have accepted; a value outside the
vocabulary satisfies nothing.

### `acr` versus the assurance block

Do not confuse `acr` with `assurance()`. `acr` grades *this login event*. The
**assurance block** (`$login->assurance()`) describes the *identity behind it*
-- how the person was verified at enrolment: the `uniqueness` basis, the
`verified_on` month, whether chip liveness was proven, the `trust_tier`, and the
device's `key_protection`. One is about now; the other is about who they are. A
high-value flow usually wants both: `acr: 'zoreal.live'` for presence, and the
assurance block for the strength of the underlying identity proofing.

## What each call does

| Call | What happens |
|---|---|
| `authenticate($code, $codeVerifier, $nonce = null, $acr = null)` | `exchange` + `verifyIdToken`, returns a `Login` |
| `exchange($code, $codeVerifier)` | `POST {issuer}/token` with your registered client authentication |
| `verifyIdToken($jwt, $nonce = null, $acr = null)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, `nonce` when given, and the `acr` floor when required |
| `userinfo($accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login::userinfo()` | the above, once, memoized; `[]` when there is no access token |

`Login` reads the ID token claims directly -- `sub()`, `acr()`, `live()`,
`satisfiesAcr('zoreal.device')`, `amr()`, `assurance()`, `ageOver(18)`,
`nationality()` -- and the `/userinfo` claims
lazily: `email()`, `emailVerified()`, `name()`, `givenName()`, `familyName()`,
`birthdate()`, `documentType()`, `documentNumber()`, `issuingCountry()`,
`documentExpiresOn()`, `portrait()`.

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

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans -- only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; GDPR Article 9 data) | `/userinfo` | C | confidential client + verified domain -- *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client, so the
  no-backend browser button can use it. **Tier B and C** are personal data,
  served only from `/userinfo` to a confidential client on a domain you have
  verified, and never placed in a browser token.
- **Age thresholds are a fixed set** -- 13, 16, 18, 21, 65 -- that you register
  on the asset. `$login->ageOver($n)` returns `null` for a threshold you did not
  register (no claim was minted), which is different from `false`. The set is
  fixed on purpose: registering all five would let a site recover the age band.

## Error reference

`exchange()` / `authenticate()` throw `ExchangeError`, which carries the
provider's own `$oauthError` code, `$description` and HTTP `$status` verbatim.
What you will actually see at `/token`:

| `$oauthError` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent -- unknown, expired (60s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed -- wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth` (not accepted at `/token` yet) | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

A failure to reach the endpoint at all (DNS, TLS, timeout) surfaces the same
way: an `ExchangeError` whose `$oauthError` is `server_error`. That one *is*
transient -- a retry is reasonable where the three above are not.

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError`), so handle them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE/nonce, an unverified sector, an unregistered `redirect_uri`, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume -- the expected quiet outcome, not a failure |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app -- **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet -- offer to try again |

`request_denied` is a person choosing not to sign in, not a fault. Treat it like
a cancelled dialog: clear any spinner and offer the button again, do not log it
as a failure or show a red error.

This package's own exception classes, all extending `OAuth2Error` so one
`catch` can take the whole family:

| Class | Means |
|---|---|
| `ConfigurationError` | You built the `Client`/`ClientAuth` wrong, or asked to verify an `acr` outside the vocabulary -- a bug in your code, not a bad token |
| `ExchangeError` | The provider refused the code exchange; carries `$oauthError`, `$description`, `$status` |
| `VerificationError` | The ID token did not verify -- signature, `iss`, `aud`, `exp`, `nonce`, a non-ES256 algorithm, or the `acr` floor. A JWKS that could not be fetched or parsed is this too, because it leaves the token unverifiable |
| `UserinfoError` | The `/userinfo` call failed. A returning user matched on `sub` can survive a caught one; a signup that needs the email cannot |

`OAuth2Error` is the shared base; a transport failure (`TransportError`,
internal) is caught by the `Client` and rethrown as the domain error of the
call in flight, so you only ever handle the four above. No error message in this
package ever carries a token, a secret or a key.

## The assurance block

`$login->assurance()` is the ID token's `zoreal` claim -- an array describing the
strength of the *identity* behind this login (distinct from `acr`, which grades
the *login event*), or `null` when the token carries none. Its keys and their
value sets:

| Key | Values | Meaning |
|---|---|---|
| `uniqueness` | `personal_number` \| `document` \| `none` | The anchor the holder is deduplicated on. `personal_number` (a national number from the chip) is strongest; `none` means no reliable anchor |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. Quantised to a month on purpose -- a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `true` \| `false` | Whether the passport chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `high` \| `standard` | `high` when `chip_liveness_proven`, else `standard` |
| `key_protection` | `secure_enclave` \| `strongbox` \| `tee` \| `software` | How the holder's device key is protected. `software` means no hardware attestation |

A high-value flow usually pairs `acr: 'zoreal.live'` (fresh presence) with a
check on the assurance block (identity strength) -- e.g. requiring
`uniqueness === 'personal_number'` and `trust_tier === 'high'`:

```php
$a = $login->assurance() ?? [];
if (($a['uniqueness'] ?? null) !== 'personal_number' || ($a['trust_tier'] ?? null) !== 'high') {
    // not strong enough for this action -- refuse or step up
}
```

## A complete example

A plain PHP login handler, end to end -- the shape a real integration takes.
Adapt the `$users` calls to your own persistence; the ZOREAL parts are exact.

```php
<?php
// POST /auth/zoreal
//
// Your frontend's ZorealLogin onSuccess posts { code, code_verifier, nonce }
// here over your own TLS. Protect this endpoint with your normal CSRF /
// same-origin controls, exactly as you would any login route -- the ZOREAL
// nonce protects the token, not your endpoint.

use Zoreal\OAuth2\Client;
use Zoreal\OAuth2\ClientAuth;
use Zoreal\OAuth2\ExchangeError;
use Zoreal\OAuth2\VerificationError;
use Zoreal\OAuth2\UserinfoError;

$zoreal = new Client(
    clientId: $_ENV['ZOREAL_CLIENT_ID'],
    auth: ClientAuth::clientSecretBasic($_ENV['ZOREAL_CLIENT_SECRET']),
);

$body = json_decode((string) file_get_contents('php://input'), true) ?: [];
header('Content-Type: application/json');

try {
    $login = $zoreal->authenticate(
        code: $body['code'] ?? '',
        codeVerifier: $body['code_verifier'] ?? '',
        nonce: $body['nonce'] ?? null,
        // acr: 'zoreal.live',   // add for a step-up / high-value login
    );

    $user = $users->findByProviderUid('zoreal', $login->sub());
    if ($user === null) {
        // Claim an existing account that owns this verified email rather than
        // colliding on the unique index; otherwise create one.
        if ($login->emailVerified()) {
            $user = $users->findByEmail($login->email());
        }
        $user ??= $users->create([
            'email' => $login->email(),
            'name'  => $login->name(),
        ]);
        $users->linkProvider($user, 'zoreal', $login->sub());
    }

    session_regenerate_id(true);            // fixation defence
    $_SESSION['user_id'] = $user->id;
    echo json_encode(['ok' => true]);
} catch (ExchangeError | VerificationError $e) {
    // A spent code or a token that did not verify: the login must be restarted.
    error_log('ZOREAL login failed: ' . $e->getMessage());
    http_response_code(401);
    echo json_encode(['error' => 'sign_in_failed']);
} catch (UserinfoError $e) {
    // Personal data was unreachable. Fine for a returning user matched on sub;
    // fatal for a signup that needs the email.
    http_response_code(401);
    echo json_encode(['error' => 'sign_in_failed']);
}
```

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
- **Always pass the nonce through, and protect your own endpoint too.** The SDK
  generates the nonce and gives it to your frontend in `onSuccess`; passing it
  here lets the package confirm the ID token was minted for *this* login rather
  than substituted. Two things it does **not** do: it is not your endpoint's
  CSRF token (protect your `/auth/zoreal` route with your framework's normal
  CSRF / same-origin defence), and PKCE -- not the nonce -- is what proves
  whoever exchanges the code is whoever started the flow.
- **The `issuer` must match the token's `iss` exactly** -- it is compared, not
  normalized. Production is `https://id.zoreal.com`; override `issuer:` only
  when you have been given a non-production provider to point at.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **`portrait` is registrable and not served yet.** The provider does not
  return the claim today; `Login::portrait()` exists so your code does not
  change when it starts to.
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

## License

MIT.
</content>
</invoke>
