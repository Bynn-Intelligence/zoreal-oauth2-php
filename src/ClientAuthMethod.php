<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * The four token_endpoint_auth_method values a ZOREAL client can register.
 * The method is chosen at registration in the dashboard; what you build a
 * ClientAuth with here has to be the same one, because the provider
 * authenticates the exchange against what was registered, not against what
 * arrives.
 */
enum ClientAuthMethod: string
{
    /**
     * Public client: no secret, no key. PKCE is the only proof, which is why
     * a public client can only ever have been granted Tier A scopes.
     */
    case None = 'none';

    /**
     * Confidential client with a shared secret. The secret travels as HTTP
     * Basic, never as a form field.
     */
    case ClientSecretBasic = 'client_secret_basic';

    /**
     * Confidential client with a private key (RFC 7523). This library builds
     * and signs a fresh 60-second assertion per exchange; the provider
     * verifies it against the public JWKS you registered.
     */
    case PrivateKeyJwt = 'private_key_jwt';

    /**
     * Mutual-TLS client certificate. Registrable, and the provider currently
     * answers the token exchange with 501; see ClientAuth::tlsClientAuth().
     */
    case TlsClientAuth = 'tls_client_auth';
}
