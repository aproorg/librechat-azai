jest.mock('@librechat/data-schemas', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), debug: jest.fn(), error: jest.fn() },
  DEFAULT_SESSION_EXPIRY: 900000,
  DEFAULT_REFRESH_TOKEN_EXPIRY: 604800000,
}));
jest.mock('librechat-data-provider', () => ({
  ErrorTypes: {},
  SystemRoles: { USER: 'USER', ADMIN: 'ADMIN' },
  errorsToString: jest.fn(),
}));
jest.mock('@librechat/api', () => ({
  isEnabled: jest.fn((val) => val === 'true' || val === true),
  checkEmailConfig: jest.fn(),
  isEmailDomainAllowed: jest.fn(),
  math: jest.fn((val, fallback) => (val ? Number(val) : fallback)),
  shouldUseSecureCookie: jest.fn(() => false),
  resolveAppConfigForUser: jest.fn(async (_getAppConfig, _user) => ({})),
  getCloudFrontConfig: jest.fn(() => null),
  setCloudFrontCookies: jest.fn(),
  parseCloudFrontCookieScope: jest.fn(),
  CLOUDFRONT_SCOPE_COOKIE: 'cf_scope',
}));
jest.mock('~/models', () => ({
  findUser: jest.fn(),
  findToken: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
  countUsers: jest.fn(),
  getUserById: jest.fn(),
  findSession: jest.fn(),
  createToken: jest.fn(),
  deleteTokens: jest.fn(),
  deleteSession: jest.fn(),
  createSession: jest.fn(),
  generateToken: jest.fn(),
  deleteUserById: jest.fn(),
  generateRefreshToken: jest.fn(),
}));
jest.mock('~/strategies/validators', () => ({ registerSchema: { parse: jest.fn() } }));
jest.mock('~/server/services/Config', () => ({ getAppConfig: jest.fn() }));
jest.mock('~/server/utils', () => ({ sendEmail: jest.fn() }));

jest.mock('openid-client', () => ({
  refreshTokenGrant: jest.fn(),
}));
jest.mock('~/strategies/openidStrategy', () => ({
  getOpenIdConfig: jest.fn(() => ({ mockConfig: true })),
}));

const openIdClient = require('openid-client');
const { getOpenIdConfig } = require('~/strategies/openidStrategy');
const { logger } = require('@librechat/data-schemas');
const { refreshOpenIDTokensFromCookie } = require('./AuthService');

function mockResponse() {
  const cookies = {};
  return {
    cookie: jest.fn((name, value, options) => {
      cookies[name] = { value, options };
    }),
    _cookies: cookies,
  };
}

function mockRequest({ cookieHeader = '', session = null } = {}) {
  return {
    headers: cookieHeader ? { cookie: cookieHeader } : {},
    session,
  };
}

describe('refreshOpenIDTokensFromCookie', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns null and does not call IdP when refresh cookie is missing', async () => {
    const req = mockRequest({ cookieHeader: 'token_provider=openid' });
    const res = mockResponse();

    const result = await refreshOpenIDTokensFromCookie(req, res, 'user-id-123');

    expect(result).toBeNull();
    expect(openIdClient.refreshTokenGrant).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalled();
  });
});

describe('refreshOpenIDTokensFromCookie - IdP interactions', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.OPENID_SCOPE = 'openid profile email';
  });

  afterEach(() => {
    delete process.env.OPENID_SCOPE;
  });

  it('successfully refreshes tokens and writes them via setOpenIDAuthTokens', async () => {
    const tokenset = {
      access_token: 'new-access',
      id_token: 'new-id',
      refresh_token: 'new-refresh',
    };
    openIdClient.refreshTokenGrant.mockResolvedValueOnce(tokenset);

    const req = mockRequest({
      cookieHeader: 'refreshToken=current-refresh',
      session: {},
    });
    const res = mockResponse();

    const result = await refreshOpenIDTokensFromCookie(req, res, 'user-id-123');

    expect(result).toBe(tokenset);
    expect(getOpenIdConfig).toHaveBeenCalledTimes(1);
    expect(openIdClient.refreshTokenGrant).toHaveBeenCalledWith(
      { mockConfig: true },
      'current-refresh',
      { scope: 'openid profile email' },
    );
    // setOpenIDAuthTokens should have been called — its side effect is
    // populating req.session.openidTokens.
    expect(req.session.openidTokens).toBeDefined();
    expect(req.session.openidTokens.accessToken).toBe('new-access');
    expect(req.session.openidTokens.idToken).toBe('new-id');
  });

  it('passes empty params object when OPENID_SCOPE is unset', async () => {
    delete process.env.OPENID_SCOPE;
    openIdClient.refreshTokenGrant.mockResolvedValueOnce({
      access_token: 'a',
      id_token: 'i',
      refresh_token: 'r',
    });

    const req = mockRequest({
      cookieHeader: 'refreshToken=rt',
      session: {},
    });
    await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');

    expect(openIdClient.refreshTokenGrant).toHaveBeenCalledWith({ mockConfig: true }, 'rt', {});
  });

  it('returns null and warns when getOpenIdConfig throws', async () => {
    getOpenIdConfig.mockImplementationOnce(() => {
      throw new Error('not configured');
    });

    const req = mockRequest({
      cookieHeader: 'refreshToken=rt',
      session: {},
    });
    const result = await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');

    expect(result).toBeNull();
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('refreshOpenIDTokensFromCookie'),
      expect.any(Error),
    );
    expect(openIdClient.refreshTokenGrant).not.toHaveBeenCalled();
  });

  it('returns null and warns when refreshTokenGrant rejects', async () => {
    openIdClient.refreshTokenGrant.mockRejectedValueOnce(new Error('invalid_grant'));

    const req = mockRequest({
      cookieHeader: 'refreshToken=rt',
      session: {},
    });
    const result = await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');

    expect(result).toBeNull();
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('refreshOpenIDTokensFromCookie'),
      expect.any(Error),
    );
  });

  it('returns null and warns when tokenset has no access_token', async () => {
    // setOpenIDAuthTokens early-returns undefined when access_token is missing
    openIdClient.refreshTokenGrant.mockResolvedValueOnce({
      id_token: 'i',
      refresh_token: 'r',
      // access_token missing
    });

    const req = mockRequest({
      cookieHeader: 'refreshToken=rt',
      session: {},
    });
    const result = await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');

    expect(result).toBeNull();
    expect(logger.warn).toHaveBeenCalled();
  });

  it('returns null and warns when res is missing', async () => {
    const req = mockRequest({
      cookieHeader: 'refreshToken=rt',
      session: {},
    });

    const result = await refreshOpenIDTokensFromCookie(req, undefined, 'uid');

    expect(result).toBeNull();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('No res object'));
    expect(openIdClient.refreshTokenGrant).not.toHaveBeenCalled();
  });
});

describe('refreshOpenIDTokensFromCookie - dedup behavior', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('deduplicates concurrent calls with the same refresh token', async () => {
    const tokenset = {
      access_token: 'a',
      id_token: 'i',
      refresh_token: 'r',
    };
    // Use a manually-controlled promise so both calls are in-flight at once
    let resolveGrant;
    openIdClient.refreshTokenGrant.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveGrant = resolve;
      }),
    );

    const req1 = mockRequest({ cookieHeader: 'refreshToken=shared', session: {} });
    const req2 = mockRequest({ cookieHeader: 'refreshToken=shared', session: {} });

    const p1 = refreshOpenIDTokensFromCookie(req1, mockResponse(), 'uid');
    const p2 = refreshOpenIDTokensFromCookie(req2, mockResponse(), 'uid');

    resolveGrant(tokenset);
    const [r1, r2] = await Promise.all([p1, p2]);

    expect(r1).toBe(tokenset);
    expect(r2).toBe(tokenset);
    expect(openIdClient.refreshTokenGrant).toHaveBeenCalledTimes(1);
  });

  it('releases the dedup entry after success — sequential calls each hit the IdP', async () => {
    const tokenset = {
      access_token: 'a',
      id_token: 'i',
      refresh_token: 'r',
    };
    openIdClient.refreshTokenGrant.mockResolvedValue(tokenset);

    const req = mockRequest({ cookieHeader: 'refreshToken=same', session: {} });

    await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');
    await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');

    expect(openIdClient.refreshTokenGrant).toHaveBeenCalledTimes(2);
  });

  it('releases the dedup entry after failure — subsequent calls retry', async () => {
    openIdClient.refreshTokenGrant.mockRejectedValueOnce(new Error('first failure'));
    openIdClient.refreshTokenGrant.mockResolvedValueOnce({
      access_token: 'a',
      id_token: 'i',
      refresh_token: 'r',
    });

    const req = mockRequest({ cookieHeader: 'refreshToken=same', session: {} });

    const r1 = await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');
    expect(r1).toBeNull();

    const r2 = await refreshOpenIDTokensFromCookie(req, mockResponse(), 'uid');
    expect(r2).not.toBeNull();
    expect(openIdClient.refreshTokenGrant).toHaveBeenCalledTimes(2);
  });

  it('concurrent calls share a single failure result', async () => {
    let rejectGrant;
    openIdClient.refreshTokenGrant.mockReturnValueOnce(
      new Promise((_resolve, reject) => {
        rejectGrant = reject;
      }),
    );

    const req1 = mockRequest({ cookieHeader: 'refreshToken=shared', session: {} });
    const req2 = mockRequest({ cookieHeader: 'refreshToken=shared', session: {} });

    const p1 = refreshOpenIDTokensFromCookie(req1, mockResponse(), 'uid');
    const p2 = refreshOpenIDTokensFromCookie(req2, mockResponse(), 'uid');

    rejectGrant(new Error('grant failed'));
    const [r1, r2] = await Promise.all([p1, p2]);

    expect(r1).toBeNull();
    expect(r2).toBeNull();
    expect(openIdClient.refreshTokenGrant).toHaveBeenCalledTimes(1);
  });
});
