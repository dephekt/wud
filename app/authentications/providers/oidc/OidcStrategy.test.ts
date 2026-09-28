// @ts-nocheck
import OidcStrategy from './OidcStrategy';

let oidcStrategy: any;

beforeEach(async () => {
    oidcStrategy = new OidcStrategy();
    oidcStrategy.success = jest.fn();
    oidcStrategy.fail = jest.fn();
});

test('authenticate should return user from session if so', async () => {
    const user = { username: 'session-user' };
    oidcStrategy.authenticate({ isAuthenticated: () => true, user });
    expect(oidcStrategy.success).toHaveBeenCalledWith(user);
});

test('authenticate should fail when there is no session', async () => {
    oidcStrategy.authenticate({ isAuthenticated: () => false, headers: {} });
    expect(oidcStrategy.fail).toHaveBeenCalledWith(401);
});

test('authenticate should not accept a bearer token', async () => {
    oidcStrategy.authenticate({
        isAuthenticated: () => false,
        headers: { authorization: 'Bearer XXXXX' },
    });
    expect(oidcStrategy.success).not.toHaveBeenCalled();
    expect(oidcStrategy.fail).toHaveBeenCalledWith(401);
});
