import express from 'express';
import request from 'supertest';
import * as auth from './auth';
import * as registry from '../registry';
import { countLocalUsers } from '../store/user';

jest.mock('./SqliteSessionStore', () => {
    const session = require('express-session');
    return jest.fn().mockImplementation(() => new session.MemoryStore());
});

jest.mock('../store/user', () => ({
    getUserById: jest.fn(),
    countLocalUsers: jest.fn(),
}));

jest.mock('../store', () => ({
    store: {
        getConfiguration: jest.fn(() => ({
            path: '/tmp',
            file: 'wud.sqlite',
        })),
    },
}));

jest.mock('../registry', () => ({
    getState: jest.fn(() => ({
        authentication: {
            mockAuth: {
                getId: () => 'mockAuth',
                getStrategy: () => ({ name: 'mockStrategy' }),
                getStrategyDescription: () => ({
                    type: 'mock',
                    name: 'Mock Auth',
                    logoutUrl: 'http://logout',
                }),
            },
        },
    })),
}));

jest.mock('getmac', () => jest.fn(() => '00:00:00:00:00:00'));
jest.mock('uuid', () => ({
    v5: jest.fn(() => '12345678-1234-5678-1234-567812345678'),
}));

jest.mock('../configuration', () => ({
    getVersion: jest.fn(() => '1.0.0'),
    getLogLevel: jest.fn(() => 'info'),
}));

describe('API Auth', () => {
    let app: express.Express;

    beforeEach(() => {
        jest.clearAllMocks();
        (registry.getState as jest.Mock).mockReturnValue({
            authentication: {
                mockAuth: {
                    getId: () => 'mockAuth',
                    getStrategy: () => ({ name: 'mockStrategy' }),
                    getStrategyDescription: () => ({
                        type: 'mock',
                        name: 'Mock Auth',
                        logoutUrl: 'http://logout',
                    }),
                },
            },
        });
        (countLocalUsers as jest.Mock).mockResolvedValue(1);
        app = express();
        app.use(express.json());

        // Mock passport authentication middleware so it passes
        const passport = require('passport');
        jest.spyOn(passport, 'authenticate').mockImplementation(
            () => (req: any, res: any, next: any) => {
                req.user = { username: 'testuser' };
                req.isAuthenticated = () => true;
                next();
            },
        );
        jest.spyOn(passport, 'initialize').mockImplementation(
            () => (req: any, res: any, next: any) => {
                req.logout = jest.fn((cb: any) => {
                    if (typeof cb === 'function') cb(null);
                });
                req.isAuthenticated = () => true;
                req.user = { username: 'testuser' };
                next();
            },
        );
        jest.spyOn(passport, 'session').mockImplementation(
            () => (req: any, res: any, next: any) => next(),
        );

        auth.init(app);
    });

    test('GET /auth/strategies should return unique strategies', async () => {
        const res = await request(app).get('/auth/strategies');
        expect(res.status).toBe(200);
        expect(res.body).toEqual([
            { type: 'mock', name: 'Mock Auth', logoutUrl: 'http://logout' },
        ]);
    });

    test('GET /auth/strategies should exclude basic strategy when countLocalUsers is 0', async () => {
        (countLocalUsers as jest.Mock).mockResolvedValue(0);
        (registry.getState as jest.Mock).mockReturnValue({
            authentication: {
                basicAuth: {
                    getId: () => 'basicAuth',
                    getStrategy: () => ({ name: 'basic' }),
                    getStrategyDescription: () => ({
                        type: 'basic',
                        name: 'Local Credentials',
                    }),
                },
                oidcAuth: {
                    getId: () => 'oidcAuth',
                    getStrategy: () => ({ name: 'oidc' }),
                    getStrategyDescription: () => ({
                        type: 'oidc',
                        name: 'Keycloak',
                    }),
                },
            },
        });

        const res = await request(app).get('/auth/strategies');
        expect(res.status).toBe(200);
        expect(res.body).toEqual([{ type: 'oidc', name: 'Keycloak' }]);
        expect(countLocalUsers).toHaveBeenCalled();
    });

    test('GET /auth/strategies should include basic strategy when countLocalUsers > 0', async () => {
        (countLocalUsers as jest.Mock).mockResolvedValue(2);
        (registry.getState as jest.Mock).mockReturnValue({
            authentication: {
                basicAuth: {
                    getId: () => 'basicAuth',
                    getStrategy: () => ({ name: 'basic' }),
                    getStrategyDescription: () => ({
                        type: 'basic',
                        name: 'Local Credentials',
                    }),
                },
                oidcAuth: {
                    getId: () => 'oidcAuth',
                    getStrategy: () => ({ name: 'oidc' }),
                    getStrategyDescription: () => ({
                        type: 'oidc',
                        name: 'Keycloak',
                    }),
                },
            },
        });

        const res = await request(app).get('/auth/strategies');
        expect(res.status).toBe(200);
        expect(res.body).toEqual([
            { type: 'oidc', name: 'Keycloak' },
            { type: 'basic', name: 'Local Credentials' },
        ]);
        expect(countLocalUsers).toHaveBeenCalled();
    });

    test('POST /auth/login should return user', async () => {
        const res = await request(app).post('/auth/login');
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ username: 'testuser' });
    });

    test('GET /auth/user should return current user', async () => {
        const res = await request(app).get('/auth/user');
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ username: 'testuser' });
    });

    test('POST /auth/logout should clear session', async () => {
        // We override the passport mock to mock req.logout
        const tempApp = express();
        tempApp.use(express.json());
        auth.init(tempApp);
        tempApp.use((err: any, req: any, res: any) => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });

        const res = await request(tempApp).post('/auth/logout');
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('logoutUrl');
    });

    test('requireAuthentication middleware should proceed if authenticated', () => {
        const req = { isAuthenticated: () => true } as any;
        const res = {} as any;
        const next = jest.fn();
        auth.requireAuthentication(req, res, next);
        expect(next).toHaveBeenCalled();
    });

    test('requireAuthentication middleware should call passport if not authenticated', () => {
        const req = { isAuthenticated: () => false } as any;
        const res = {} as any;
        const next = jest.fn();

        auth.requireAuthentication(req, res, next);
        // Since we mocked passport.authenticate to call next() and set user
        expect(req.user).toEqual({ username: 'testuser' });
        expect(next).toHaveBeenCalled();
    });

    describe('requireAuthentication with a bearer token', () => {
        const bearer = (token: string) =>
            ({
                isAuthenticated: () => false,
                headers: { authorization: `Bearer ${token}` },
            }) as any;
        const response = () => {
            const res: any = {};
            res.set = jest.fn().mockReturnValue(res);
            res.status = jest.fn().mockReturnValue(res);
            res.json = jest.fn().mockReturnValue(res);
            return res;
        };
        const accessTokenAuth = (verifyAccessToken: jest.Mock) => ({
            getId: () => 'oidc.keycloak',
            acceptsAccessTokens: () => true,
            verifyAccessToken,
        });
        const withAuthentications = (authentication: object) =>
            (registry.getState as jest.Mock).mockReturnValue({
                authentication,
            });

        test('should send wud_ tokens to the API token strategy', () => {
            const verifyAccessToken = jest.fn();
            withAuthentications({ oidc: accessTokenAuth(verifyAccessToken) });
            const passport = require('passport');
            const next = jest.fn();

            auth.requireAuthentication(bearer('wud_abc'), response(), next);

            expect(passport.authenticate).toHaveBeenCalledWith('bearer', {
                session: false,
            });
            expect(verifyAccessToken).not.toHaveBeenCalled();
            expect(next).toHaveBeenCalled();
        });

        test('should keep the API token strategy when no authentication accepts access tokens', () => {
            withAuthentications({
                basic: { acceptsAccessTokens: () => false },
            });
            const passport = require('passport');

            auth.requireAuthentication(
                bearer('eyJ.jwt'),
                response(),
                jest.fn(),
            );

            expect(passport.authenticate).toHaveBeenCalledWith('bearer', {
                session: false,
            });
        });

        test('should authenticate a valid access token', async () => {
            const user = {
                username: 'svc',
                role: 'rw',
                token: { scopes: ['read', 'write'] },
            };
            withAuthentications({
                basic: { acceptsAccessTokens: () => false },
                oidc: accessTokenAuth(jest.fn().mockResolvedValue(user)),
            });
            const req = bearer('eyJ.jwt');
            const next = jest.fn();

            await auth.requireAuthentication(req, response(), next);

            expect(req.user).toBe(user);
            expect(next).toHaveBeenCalledWith();
        });

        test('should try each authentication that accepts access tokens', async () => {
            const second = jest.fn().mockResolvedValue({ username: 'svc' });
            withAuthentications({
                first: accessTokenAuth(jest.fn().mockResolvedValue(undefined)),
                second: accessTokenAuth(second),
            });
            const next = jest.fn();

            await auth.requireAuthentication(
                bearer('eyJ.jwt'),
                response(),
                next,
            );

            expect(second).toHaveBeenCalledWith('eyJ.jwt');
            expect(next).toHaveBeenCalledWith();
        });

        test('should reject an invalid access token with 401', async () => {
            withAuthentications({
                oidc: accessTokenAuth(jest.fn().mockResolvedValue(undefined)),
            });
            const res = response();
            const next = jest.fn();

            await auth.requireAuthentication(bearer('eyJ.jwt'), res, next);

            expect(res.set).toHaveBeenCalledWith(
                'WWW-Authenticate',
                'Bearer error="invalid_token"',
            );
            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });

        test('should pass verification errors to the error handler', async () => {
            const error = new Error('store unavailable');
            withAuthentications({
                oidc: accessTokenAuth(jest.fn().mockRejectedValue(error)),
            });
            const next = jest.fn();

            await auth.requireAuthentication(
                bearer('eyJ.jwt'),
                response(),
                next,
            );

            expect(next).toHaveBeenCalledWith(error);
        });
    });

    test('getAllIds should return registered strategy ids', () => {
        const ids = auth.getAllIds();
        expect(ids).toContain('mockAuth');
    });
});
