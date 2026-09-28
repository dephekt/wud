import { Strategy } from 'passport';
import { Request } from 'express';

/**
 * Passport strategy for an OIDC login session.
 * The login itself happens through the redirect/callback routes; bearer
 * access tokens are validated by requireAuthentication, not here.
 */
class OidcStrategy extends Strategy {
    authenticate(req: Request) {
        if (req.isAuthenticated()) {
            this.success(req.user);
        } else {
            this.fail(401);
        }
    }
}

export default OidcStrategy;
