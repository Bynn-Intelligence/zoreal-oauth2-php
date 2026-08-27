<?php

declare(strict_types=1);

namespace Zoreal\OAuth2;

/**
 * /userinfo answered with anything but the claims. Callers that can live
 * without personal data (a returning user matched by sub) may catch this
 * and continue; callers that need the email should not.
 */
class UserinfoError extends OAuth2Error
{
}
