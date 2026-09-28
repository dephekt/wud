import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';
import Authentication from '../Authentication';
import OidcStrategy from './OidcStrategy';
import { getPublicUrl } from '../../../configuration';
import { Express, Request, Response } from 'express';
import {
    getUserByUsername,
    createUser,
    updateUser,
    UserRole,
} from '../../../store/user';
import { ApiToken, ApiTokenScope } from '../../../store/token';

const DEFAULT_ACCESS_TOKEN_ALGORITHMS = ['RS256', 'ES256', 'PS256'];

const splitList = (value?: string) =>
    (value ?? '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);

export interface OidcUser {
    id: string;
    username: string;
    role: UserRole;
    provider: string;
    preferences?: unknown;
    token?: ApiToken;
}

// Extend express-session to store OIDC data in session
declare module 'express-session' {
    interface SessionData {
        oidc: {
            codeVerifier: string;
            state?: string;
            next?: string;
        };
    }
}

/**
 * OIDC authentication.
 */
class Oidc extends Authentication {
    /**
     * Get the Trigger configuration schema.
     */
    getConfigurationSchema() {
        return this.joi.object().keys({
            discovery: this.joi.string().uri().required(),
            clientid: this.joi.string().required(),
            clientsecret: this.joi.string().required(),
            redirect: this.joi.boolean().default(false),
            timeout: this.joi.number().greater(500).default(5000),
            ttl: this.joi.number().min(-1).default(60),
            usernameclaim: this.joi.string().default('email'),
            admingroup: this.joi.string().optional(),
            rwgroup: this.joi.string().optional(),
            rogroup: this.joi.string().optional(),
            defaultrole: this.joi.string().valid('ro', 'none').default('ro'),
            groupsclaim: this.joi.string().default('groups'),
            scope: this.joi.string().optional(),
            audience: this.joi.string().optional(),
            allowedclients: this.joi.string().optional(),
            algorithms: this.joi.string().optional(),
        });
    }

    /**
     * Sanitize sensitive data
     */
    maskConfiguration() {
        return {
            ...this.configuration,
            clientid: Oidc.mask(this.configuration.clientid),
            clientsecret: Oidc.mask(this.configuration.clientsecret),
        };
    }

    private cachedConfig: client.Configuration | undefined;
    private discoveryCachedAt: number | undefined;
    private logoutUrl: string | undefined;
    private discoveryPromise: Promise<void> | undefined;
    private jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
    private jwksUri: string | undefined;

    private async discoverConfiguration() {
        this.log.debug(
            `Discovering configuration from ${this.configuration.discovery}`,
        );

        const discoveryUrl = new URL(this.configuration.discovery);
        const isHttp = discoveryUrl.protocol === 'http:';
        const execute = isHttp ? [client.allowInsecureRequests] : undefined;

        this.cachedConfig = await client.discovery(
            discoveryUrl,
            this.configuration.clientid,
            this.configuration.clientsecret,
            undefined,
            {
                timeout: this.configuration.timeout,
                execute,
            },
        );
        if (isHttp) {
            client.allowInsecureRequests(this.cachedConfig);
        }
        this.discoveryCachedAt = Date.now();

        try {
            this.logoutUrl = client
                .buildEndSessionUrl(this.cachedConfig)
                .toString();
        } catch (e) {
            this.log.warn(` End session url is not supported (${e.message})`);
        }
    }

    private isDiscoveryCacheValid() {
        if (!this.cachedConfig || this.discoveryCachedAt === undefined) {
            return false;
        }

        if (this.configuration.ttl === -1) {
            return true;
        }

        return (
            Date.now() - this.discoveryCachedAt <
            this.configuration.ttl * 60_000
        );
    }

    private async ensureDiscovered(): Promise<client.Configuration>;
    private async ensureDiscovered(
        throwOnError: true,
    ): Promise<client.Configuration>;
    private async ensureDiscovered(
        throwOnError: false,
    ): Promise<client.Configuration | undefined>;
    private async ensureDiscovered(
        throwOnError = true,
    ): Promise<client.Configuration | undefined> {
        if (this.isDiscoveryCacheValid()) {
            return this.cachedConfig;
        }

        if (this.cachedConfig) {
            this.log.debug(
                `OIDC discovery cache expired after ${this.configuration.ttl} minute(s) => refresh configuration`,
            );
            this.cachedConfig = undefined;
            this.discoveryCachedAt = undefined;
            this.logoutUrl = undefined;
        }

        if (!this.discoveryPromise) {
            this.discoveryPromise = this.discoverConfiguration().finally(() => {
                this.discoveryPromise = undefined;
            });
        }

        try {
            await this.discoveryPromise;
        } catch (e) {
            if (throwOnError) {
                throw e;
            }
            this.log.warn(
                `Unable to discover OIDC authority (${(e as Error).message})`,
            );
            return undefined;
        }

        if (!this.cachedConfig && throwOnError) {
            throw new Error('OIDC configuration is not available');
        }
        return this.cachedConfig;
    }

    async initAuthentication() {
        await this.ensureDiscovered(false);
    }

    /**
     * Compute effective OIDC scopes to request.
     */
    getEffectiveScope(config?: client.Configuration): string {
        if (this.configuration.scope) {
            return this.configuration.scope;
        }
        const scopes = ['openid', 'email', 'profile'];
        if (
            this.configuration.admingroup ||
            this.configuration.rwgroup ||
            this.configuration.rogroup
        ) {
            const scopesSupported = config?.serverMetadata()?.scopes_supported;
            // Only request 'groups' scope if the IdP explicitly declares supporting it (or if no discovery metadata available)
            if (
                !scopesSupported ||
                (Array.isArray(scopesSupported) &&
                    scopesSupported.includes('groups'))
            ) {
                scopes.push('groups');
            }
        }
        return scopes.join(' ');
    }

    /**
     * Return passport strategy.
     * @param app
     */
    getStrategy(app: Express) {
        app.get(`/auth/oidc/${this.name}/redirect`, async (req, res) => {
            try {
                await this.redirect(req, res);
            } catch (e: any) {
                this.log.warn(`Error during OIDC redirection (${e.message})`);
                res.status(500).json({ error: e.message });
            }
        });
        app.get(`/auth/oidc/${this.name}/cb`, async (req, res) => {
            try {
                await this.callback(req, res);
            } catch (e: any) {
                this.log.warn(`Error during OIDC callback (${e.message})`);
                res.status(500).send(e.message);
            }
        });
        const strategy = new OidcStrategy();
        strategy.name = 'oidc';
        return strategy;
    }

    getStrategyDescription() {
        return {
            type: 'oidc',
            name: this.name,
            redirect: this.configuration.redirect,
            logoutUrl: this.logoutUrl,
        };
    }

    async redirect(req: Request, res: Response) {
        const config = await this.ensureDiscovered();
        const codeVerifier = client.randomPKCECodeVerifier();
        const codeChallenge =
            await client.calculatePKCECodeChallenge(codeVerifier);
        const state = client.randomState();

        const parameters: Record<string, string> = {
            redirect_uri: `${getPublicUrl(req)}/auth/oidc/${this.name}/cb`,
            scope: this.getEffectiveScope(config),
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            state: state,
        };

        const rawNext = req.query.next;
        const next =
            typeof rawNext === 'string' &&
            rawNext.startsWith('/') &&
            !rawNext.startsWith('//')
                ? rawNext
                : undefined;

        req.session.oidc = {
            codeVerifier,
            state,
            next,
        };

        const authUrl = client.buildAuthorizationUrl(config, parameters);
        this.log.debug(`Build redirection url [${authUrl}]`);
        res.json({
            url: authUrl,
        });
    }

    async callback(req: Request, res: Response) {
        try {
            const config = await this.ensureDiscovered();
            this.log.debug('Validate callback data');

            const oidcChecks = req.session?.oidc;
            if (!oidcChecks) {
                throw new Error('OIDC session state not found');
            }
            const nextUrl = oidcChecks.next;
            delete req.session.oidc.next;

            const currentUrl = new URL(
                `${getPublicUrl(req)}${req.originalUrl}`,
            );

            // Authentik sends an empty state back instead of not sending it at all when PKCE is not supported, so in that case we skip the state check
            const check: client.AuthorizationCodeGrantChecks = {
                pkceCodeVerifier: oidcChecks.codeVerifier,
                expectedState: oidcChecks.state
                    ? oidcChecks.state
                    : req.query.state === ''
                      ? client.skipStateCheck
                      : undefined,
            };

            const tokenSet = await client.authorizationCodeGrant(
                config,
                currentUrl,
                check,
            );

            this.log.debug('Get user info');

            const user = await this.getUserFromAccessToken(
                tokenSet.access_token,
                tokenSet.claims(),
            );
            this.log.debug('Perform passport login');
            req.login(user, (err) => {
                if (err) {
                    this.log.warn(
                        `Error when logging the user [${err.message}]`,
                    );
                    const publicUrl = getPublicUrl(req).replace(/\/$/, '');
                    res.redirect(
                        `${publicUrl}/#/login?error=${encodeURIComponent(err.message)}`,
                    );
                } else {
                    const publicUrl = getPublicUrl(req).replace(/\/$/, '');
                    const destination = nextUrl
                        ? `${publicUrl}${nextUrl}`
                        : getPublicUrl(req);
                    this.log.debug(
                        `User authenticated => redirect to app [${destination}]`,
                    );
                    res.redirect(destination);
                }
            });
        } catch (err: any) {
            this.log.warn(`Error when logging the user [${err.message}]`);
            const publicUrl = getPublicUrl(req).replace(/\/$/, '');
            res.redirect(
                `${publicUrl}/#/login?error=${encodeURIComponent(err.message)}`,
            );
        }
    }

    /**
     * Whether this provider accepts OAuth access tokens as API bearer tokens.
     */
    acceptsAccessTokens() {
        return Boolean(this.configuration.audience);
    }

    /**
     * Validate an OAuth access token issued for this API (RFC 9068) and
     * resolve its user. The token is checked locally against the issuer's
     * signing keys; returns undefined when it is not acceptable.
     */
    async verifyAccessToken(
        accessToken: string,
    ): Promise<OidcUser | undefined> {
        if (!this.acceptsAccessTokens()) {
            return undefined;
        }
        const config = await this.ensureDiscovered(false);
        const metadata = config?.serverMetadata();
        if (!metadata?.jwks_uri) {
            this.log.warn(
                'Unable to validate access token: the issuer publishes no jwks_uri',
            );
            return undefined;
        }
        if (this.jwksUri !== metadata.jwks_uri || !this.jwks) {
            this.jwks = createRemoteJWKSet(new URL(metadata.jwks_uri), {
                timeoutDuration: this.configuration.timeout,
            });
            this.jwksUri = metadata.jwks_uri;
        }

        let payload: JWTPayload;
        try {
            ({ payload } = await jwtVerify(accessToken, this.jwks, {
                issuer: metadata.issuer,
                audience: this.configuration.audience,
                algorithms:
                    splitList(this.configuration.algorithms).length > 0
                        ? splitList(this.configuration.algorithms)
                        : DEFAULT_ACCESS_TOKEN_ALGORITHMS,
                requiredClaims: ['exp', 'sub'],
            }));
        } catch (e) {
            this.log.debug(`Access token rejected (${(e as Error).message})`);
            return undefined;
        }

        const allowedClients = splitList(this.configuration.allowedclients);
        const clientId = typeof payload.azp === 'string' ? payload.azp : '';
        if (allowedClients.length > 0 && !allowedClients.includes(clientId)) {
            this.log.warn(
                `Access token rejected: client '${clientId}' is not allowed`,
            );
            return undefined;
        }

        const username = this.getUsernameFromClaims(payload);
        if (!username) {
            this.log.warn(
                'Access token rejected: it carries no username claim',
            );
            return undefined;
        }

        let user: OidcUser;
        try {
            user = await this.resolveUser(username, payload);
        } catch {
            return undefined;
        }
        return {
            ...user,
            token: {
                id: `oidc:${payload.jti ?? payload.sub}`,
                userId: user.id,
                name: clientId || this.name,
                scopes: Oidc.getScopesFromClaim(payload.scope),
            },
        };
    }

    /**
     * Map the OAuth scope claim onto WUD API token scopes.
     */
    static getScopesFromClaim(scopeClaim: unknown): ApiTokenScope[] {
        const scopes =
            typeof scopeClaim === 'string' ? scopeClaim.split(' ') : [];
        if (scopes.includes('wud:write')) {
            return ['read', 'write'];
        }
        if (scopes.includes('wud:read')) {
            return ['read'];
        }
        return [];
    }

    private getUsernameFromClaims(
        claims: Record<string, unknown>,
    ): string | undefined {
        const username =
            claims[this.configuration.usernameclaim] ??
            claims.email ??
            claims.preferred_username;
        return username ? String(username) : undefined;
    }

    async getUserFromAccessToken(accessToken: string, claim?: client.IDToken) {
        const config = await this.ensureDiscovered();
        const userInfo = await client.fetchUserInfo(
            config,
            accessToken,
            claim?.sub ?? client.skipSubjectCheck,
        );

        // check the usernameclaim, if it doesn't exist, fall back to email then preferred_username
        let username = userInfo[this.configuration.usernameclaim]?.toString();
        if (!username) {
            this.log.warn(
                `The claim [${this.configuration.usernameclaim}] does not exist in the user info, using email instead`,
            );
            username = this.getUsernameFromClaims(userInfo);
        }

        return this.resolveUser(username || 'unknown', userInfo, claim);
    }

    /**
     * Resolve the WUD user for an identity: role from its groups, then
     * onboard or sync the stored user.
     */
    private async resolveUser(
        validUsername: string,
        claims: Record<string, unknown>,
        fallbackClaims?: Record<string, unknown>,
    ): Promise<OidcUser> {
        // Extract groups claim
        const groupsClaimKey = this.configuration.groupsclaim || 'groups';
        const rawGroups =
            claims[groupsClaimKey] || fallbackClaims?.[groupsClaimKey];
        let userGroups: string[] = [];
        if (Array.isArray(rawGroups)) {
            userGroups = rawGroups.map(String);
        } else if (typeof rawGroups === 'string') {
            userGroups = rawGroups.split(',').map((g) => g.trim());
        }

        // Determine role from groups if configured
        let determinedRole: UserRole | 'none' = this.configuration.defaultrole;
        const hasGroupConfig = Boolean(
            this.configuration.admingroup ||
                this.configuration.rwgroup ||
                this.configuration.rogroup,
        );

        if (hasGroupConfig) {
            this.log.debug(
                `Extracted user groups for '${validUsername}' via claim '${groupsClaimKey}': [${userGroups.join(', ')}]`,
            );
        }

        if (
            this.configuration.admingroup &&
            userGroups.includes(this.configuration.admingroup)
        ) {
            determinedRole = 'admin';
        } else if (
            this.configuration.rwgroup &&
            userGroups.includes(this.configuration.rwgroup)
        ) {
            determinedRole = 'rw';
        } else if (
            this.configuration.rogroup &&
            userGroups.includes(this.configuration.rogroup)
        ) {
            determinedRole = 'ro';
        }

        if (determinedRole === 'none') {
            this.log.warn(
                `Access denied for user '${validUsername}': does not belong to any authorized group.`,
            );
            throw new Error(
                'Access denied: user does not belong to any authorized group',
            );
        }

        const role: UserRole = determinedRole;

        // Check if user exists in database
        const existingUser = await getUserByUsername(validUsername);
        if (existingUser) {
            if (hasGroupConfig) {
                // If group claims are configured on OIDC, sync role from IDP
                if (existingUser.role !== role) {
                    this.log.info(
                        `Syncing OIDC user role for '${validUsername}' from '${existingUser.role}' to '${role}'`,
                    );
                    await updateUser(existingUser.id, { role });
                    existingUser.role = role;
                }
            }
            return {
                id: existingUser.id,
                username: existingUser.username,
                role: existingUser.role,
                provider: existingUser.provider,
                preferences: existingUser.preferences,
            };
        }

        // User onboarding: create new OIDC user in database
        this.log.info(
            `Onboarding new OIDC user '${validUsername}' with role '${role}'`,
        );
        const newUser = await createUser({
            username: validUsername,
            role,
            provider: 'oidc',
        });

        return {
            id: newUser.id,
            username: newUser.username,
            role: newUser.role,
            provider: newUser.provider,
            preferences: newUser.preferences,
        };
    }
}

export default Oidc;
