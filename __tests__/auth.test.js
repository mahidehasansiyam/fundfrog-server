import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import http from 'http';

// Import and spy on bcrypt and jwt (don't mock the whole module — vitest CJS interop works better this way)
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Keep original fetch for harness HTTP calls; we'll mock it only inside Google tests via vi.spyOn
const originalFetch = globalThis.fetch;

/**
 * Helper: creates a test Express app with auth routes.
 * Routes implement the spec-defined behaviour.
 */
function createAuthApp(mockUsersCollection) {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  const JWT_SECRET = 'test-secret';
  const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };

  function signToken(user) {
    return jwt.sign(
      { id: user._id ? user._id.toString() : user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' },
    );
  }

  function setTokenCookie(res, token) {
    res.cookie('token', token, COOKIE_OPTIONS);
  }

  function clearTokenCookie(res) {
    res.clearCookie('token', { path: '/' });
  }

  function sanitizeUser(user) {
    return {
      id: user._id ? user._id.toString() : user.id,
      name: user.name,
      email: user.email,
      photoURL: user.photoURL || '',
      role: user.role,
      credits: user.credits,
    };
  }

  function verifyToken(req, res, next) {
    let token = null;
    // Spec: reads from req.cookies.token FIRST, falls back to Authorization Bearer header
    if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    } else {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
      }
    }
    if (!token) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch {
      return res.status(401).json({ message: 'Invalid token.' });
    }
  }

  // --- POST /api/auth/register ---
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { name, email, password, role, photoURL } = req.body;

      if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'Name, email, password, and role are required.' });
      }

      if (!['supporter', 'creator'].includes(role)) {
        return res.status(400).json({ message: 'Role must be "supporter" or "creator".' });
      }

      const existing = await mockUsersCollection.findOne({ email });
      if (existing) {
        return res.status(400).json({ message: 'Email already registered.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const credits = role === 'supporter' ? 50 : 20;

      const user = {
        name,
        email,
        photoURL: photoURL || '',
        password: hashedPassword,
        role,
        credits,
        createdAt: new Date(),
      };

      const result = await mockUsersCollection.insertOne(user);
      const savedUser = { ...user, _id: result.insertedId };
      const token = signToken(savedUser);
      setTokenCookie(res, token);

      return res.status(201).json({ user: sanitizeUser(savedUser) });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- POST /api/auth/login ---
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
      }

      const user = await mockUsersCollection.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'Invalid email or password.' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid email or password.' });
      }

      const token = signToken(user);
      setTokenCookie(res, token);

      return res.json({ user: sanitizeUser(user) });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- POST /api/auth/google ---
  app.post('/api/auth/google', async (req, res) => {
    try {
      const { credential, access_token } = req.body;

      let email, name, picture;

      if (credential) {
        const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
        const data = await response.json();
        if (!response.ok || data.error) {
          return res.status(400).json({ message: 'Invalid Google credential.' });
        }
        email = data.email;
        name = data.name;
        picture = data.picture;
      } else if (access_token) {
        const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: { Authorization: `Bearer ${access_token}` },
        });
        const data = await response.json();
        if (!response.ok || data.error) {
          return res.status(400).json({ message: 'Invalid Google access token.' });
        }
        email = data.email;
        name = data.name;
        picture = data.picture;
      } else {
        return res.status(400).json({ message: 'Google credential or access token is required.' });
      }

      let user = await mockUsersCollection.findOne({ email });

      if (!user) {
        const credits = 50;
        const newUser = {
          name,
          email,
          photoURL: picture || '',
          password: '',
          role: 'supporter',
          credits,
          createdAt: new Date(),
        };
        const result = await mockUsersCollection.insertOne(newUser);
        user = { ...newUser, _id: result.insertedId };
      }

      const token = signToken(user);
      setTokenCookie(res, token);

      return res.json({ user: sanitizeUser(user) });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- GET /api/auth/me ---
  app.get('/api/auth/me', verifyToken, async (req, res) => {
    try {
      const user = await mockUsersCollection.findOne({ email: req.user.email });
      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      }
      return res.json({ user: sanitizeUser(user) });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- POST /api/auth/logout ---
  app.post('/api/auth/logout', (req, res) => {
    clearTokenCookie(res);
    return res.json({ message: 'Logged out successfully.' });
  });

  // Catch-all 404
  app.use((req, res) => {
    res.status(404).json({ message: `Route ${req.originalUrl} not found` });
  });

  return app;
}

/**
 * Helper: starts the app on a random port and makes requests using
 * node:http (so we don't collide with global fetch mocks for Google tests).
 */
function createTestHarness(app) {
  let server;
  let baseUrl;

  const start = () =>
    new Promise((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        baseUrl = `http://localhost:${addr.port}`;
        resolve();
      });
    });

  const stop = () =>
    new Promise((resolve) => {
      if (server) server.close(resolve);
    });

  const request = (method, path, body = undefined, headers = {}) =>
    new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const options = {
        method,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        headers: { 'Content-Type': 'application/json', ...headers },
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            const setCookie = res.headers['set-cookie']
              ? (Array.isArray(res.headers['set-cookie'])
                  ? res.headers['set-cookie'].join('; ')
                  : res.headers['set-cookie'])
              : '';
            resolve({ status: res.statusCode, body: parsed, setCookie });
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);

      if (body !== undefined) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });

  return { start, stop, request };
}

describe('Auth API (spec-based)', () => {
  let mockUsersCollection;
  let harness;

  beforeEach(() => {
    vi.clearAllMocks();

    mockUsersCollection = {
      findOne: vi.fn(),
      insertOne: vi.fn(),
    };

    const app = createAuthApp(mockUsersCollection);
    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
  });

  // ---------------------------------------------------------------
  // POST /api/auth/register
  // ---------------------------------------------------------------
  describe('POST /api/auth/register', () => {
    it('should create a supporter with 50 credits and return 201 with cookie', async () => {
      await harness.start();

      const mockInsertedId = '507f1f77bcf86cd799439011';
      mockUsersCollection.findOne.mockResolvedValue(null);
      mockUsersCollection.insertOne.mockResolvedValue({ insertedId: mockInsertedId });
      vi.spyOn(bcrypt, 'hash').mockResolvedValue('$2a$10$hashedpassword');
      vi.spyOn(jwt, 'sign').mockReturnValue('test-jwt-token');

      const result = await harness.request('POST', '/api/auth/register', {
        name: 'Jane Doe',
        email: 'jane@example.com',
        password: 'secret123',
        role: 'supporter',
      });

      expect(result.status).toBe(201);
      expect(result.body.user).toBeDefined();
      expect(result.body.user.name).toBe('Jane Doe');
      expect(result.body.user.email).toBe('jane@example.com');
      expect(result.body.user.role).toBe('supporter');
      expect(result.body.user.credits).toBe(50);
      expect(result.body.user.password).toBeUndefined();
      expect(result.setCookie).toContain('token=test-jwt-token');

      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email: 'jane@example.com' });
      expect(bcrypt.hash).toHaveBeenCalledWith('secret123', 10);
      expect(mockUsersCollection.insertOne).toHaveBeenCalled();
      const insertedUser = mockUsersCollection.insertOne.mock.calls[0][0];
      expect(insertedUser.credits).toBe(50);
      expect(insertedUser.role).toBe('supporter');
    });

    it('should create a creator with 20 credits and return 201 with cookie', async () => {
      await harness.start();

      const mockInsertedId = '507f1f77bcf86cd799439012';
      mockUsersCollection.findOne.mockResolvedValue(null);
      mockUsersCollection.insertOne.mockResolvedValue({ insertedId: mockInsertedId });
      vi.spyOn(bcrypt, 'hash').mockResolvedValue('$2a$10$hashedpassword');
      vi.spyOn(jwt, 'sign').mockReturnValue('creator-jwt-token');

      const result = await harness.request('POST', '/api/auth/register', {
        name: 'John Creator',
        email: 'john@creator.com',
        password: 'secret456',
        role: 'creator',
      });

      expect(result.status).toBe(201);
      expect(result.body.user.role).toBe('creator');
      expect(result.body.user.credits).toBe(20);
      expect(result.setCookie).toContain('token=creator-jwt-token');

      const insertedUser = mockUsersCollection.insertOne.mock.calls[0][0];
      expect(insertedUser.credits).toBe(20);
      expect(insertedUser.role).toBe('creator');
    });

    it('should return 400 when required fields are missing', async () => {
      await harness.start();

      const result1 = await harness.request('POST', '/api/auth/register', {
        name: 'No Password',
        email: 'nopass@example.com',
        role: 'supporter',
      });
      expect(result1.status).toBe(400);
      expect(result1.body.message).toContain('required');

      const result2 = await harness.request('POST', '/api/auth/register', {});
      expect(result2.status).toBe(400);
      expect(result2.body.message).toContain('required');
    });

    it('should return 400 when role is invalid', async () => {
      await harness.start();

      const result = await harness.request('POST', '/api/auth/register', {
        name: 'Bad Role',
        email: 'bad@example.com',
        password: 'secret123',
        role: 'admin',
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Role must be');
    });

    it('should return 400 when email is already registered', async () => {
      await harness.start();

      mockUsersCollection.findOne.mockResolvedValue({
        _id: 'existing-id',
        email: 'dup@example.com',
      });

      const result = await harness.request('POST', '/api/auth/register', {
        name: 'Duplicate',
        email: 'dup@example.com',
        password: 'secret123',
        role: 'supporter',
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Email already registered');
    });
  });

  // ---------------------------------------------------------------
  // POST /api/auth/login
  // ---------------------------------------------------------------
  describe('POST /api/auth/login', () => {
    it('should return 200 and set cookie for valid credentials', async () => {
      await harness.start();

      const existingUser = {
        _id: '507f1f77bcf86cd799439013',
        name: 'Existing User',
        email: 'existing@example.com',
        password: '$2a$10$hashedpassword',
        photoURL: 'http://photo.com/pic.jpg',
        role: 'supporter',
        credits: 50,
      };

      mockUsersCollection.findOne.mockResolvedValue(existingUser);
      vi.spyOn(bcrypt, 'compare').mockResolvedValue(true);
      vi.spyOn(jwt, 'sign').mockReturnValue('login-jwt-token');

      const result = await harness.request('POST', '/api/auth/login', {
        email: 'existing@example.com',
        password: 'correctpassword',
      });

      expect(result.status).toBe(200);
      expect(result.body.user).toBeDefined();
      expect(result.body.user.email).toBe('existing@example.com');
      expect(result.body.user.name).toBe('Existing User');
      expect(result.body.user.credits).toBe(50);
      expect(result.body.user.password).toBeUndefined();
      expect(result.setCookie).toContain('token=login-jwt-token');

      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email: 'existing@example.com' });
      expect(bcrypt.compare).toHaveBeenCalledWith('correctpassword', existingUser.password);
    });

    it('should return 400 for wrong password', async () => {
      await harness.start();

      const existingUser = {
        _id: '507f1f77bcf86cd799439014',
        email: 'wrongpass@example.com',
        password: '$2a$10$realhash',
        name: 'Wrong Pass',
        role: 'creator',
        credits: 20,
      };

      mockUsersCollection.findOne.mockResolvedValue(existingUser);
      vi.spyOn(bcrypt, 'compare').mockResolvedValue(false);

      const result = await harness.request('POST', '/api/auth/login', {
        email: 'wrongpass@example.com',
        password: 'wrongpassword',
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid email or password');
      expect(result.setCookie).not.toContain('token=');
    });

    it('should return 400 for non-existent email', async () => {
      await harness.start();

      mockUsersCollection.findOne.mockResolvedValue(null);

      const result = await harness.request('POST', '/api/auth/login', {
        email: 'nobody@example.com',
        password: 'anypassword',
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid email or password');
    });

    it('should return 400 when email or password is missing', async () => {
      await harness.start();

      const result1 = await harness.request('POST', '/api/auth/login', { email: 'test@test.com' });
      expect(result1.status).toBe(400);
      expect(result1.body.message).toContain('required');

      const result2 = await harness.request('POST', '/api/auth/login', {});
      expect(result2.status).toBe(400);
      expect(result2.body.message).toContain('required');
    });
  });

  // ---------------------------------------------------------------
  // GET /api/auth/me
  // ---------------------------------------------------------------
  describe('GET /api/auth/me', () => {
    it('should return user data for a valid cookie', async () => {
      await harness.start();

      const mockUser = {
        _id: '507f1f77bcf86cd799439015',
        name: 'Session User',
        email: 'session@example.com',
        photoURL: 'http://photo.com/session.jpg',
        role: 'supporter',
        credits: 50,
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: '507f1f77bcf86cd799439015',
        email: 'session@example.com',
        name: 'Session User',
        role: 'supporter',
      });

      mockUsersCollection.findOne.mockResolvedValue(mockUser);

      const result = await harness.request(
        'GET',
        '/api/auth/me',
        undefined,
        { Cookie: 'token=valid-jwt-token' },
      );

      expect(result.status).toBe(200);
      expect(result.body.user).toBeDefined();
      expect(result.body.user.email).toBe('session@example.com');
      expect(result.body.user.name).toBe('Session User');
      expect(result.body.user.role).toBe('supporter');
      expect(result.body.user.credits).toBe(50);
    });

    it('should return 401 when no cookie or Authorization header is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/auth/me');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 401 when token is invalid or expired', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new Error('jwt expired');
      });

      const result = await harness.request(
        'GET',
        '/api/auth/me',
        undefined,
        { Cookie: 'token=expired-jwt-token' },
      );

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Invalid token');
    });

    it('should support Authorization Bearer header as alternative to cookie', async () => {
      await harness.start();

      const mockUser = {
        _id: '507f1f77bcf86cd799439016',
        name: 'Bearer User',
        email: 'bearer@example.com',
        photoURL: '',
        role: 'creator',
        credits: 20,
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: '507f1f77bcf86cd799439016',
        email: 'bearer@example.com',
        name: 'Bearer User',
        role: 'creator',
      });

      mockUsersCollection.findOne.mockResolvedValue(mockUser);

      const result = await harness.request(
        'GET',
        '/api/auth/me',
        undefined,
        { Authorization: 'Bearer valid-bearer-token' },
      );

      expect(result.status).toBe(200);
      expect(result.body.user.email).toBe('bearer@example.com');
    });

    it('should prefer cookie token over Authorization Bearer header when both are provided', async () => {
      await harness.start();

      const mockUser = {
        _id: '507f1f77bcf86cd799439020',
        name: 'Cookie Priority User',
        email: 'cookiepriority@example.com',
        photoURL: '',
        role: 'supporter',
        credits: 50,
      };

      const verifySpy = vi.spyOn(jwt, 'verify').mockReturnValue({
        id: '507f1f77bcf86cd799439020',
        email: 'cookiepriority@example.com',
        name: 'Cookie Priority User',
        role: 'supporter',
      });

      mockUsersCollection.findOne.mockResolvedValue(mockUser);

      // Provide BOTH cookie and Bearer header — cookie must take precedence
      const result = await harness.request(
        'GET',
        '/api/auth/me',
        undefined,
        {
          Cookie: 'token=valid-cookie-token',
          Authorization: 'Bearer invalid-bearer-token',
        },
      );

      expect(result.status).toBe(200);
      // Verify that cookie token was used (not the Bearer token which would also appear valid)
      expect(verifySpy).toHaveBeenCalledWith('valid-cookie-token', expect.any(String));
    });
  });

  // ---------------------------------------------------------------
  // POST /api/auth/logout
  // ---------------------------------------------------------------
  describe('POST /api/auth/logout', () => {
    it('should clear the token cookie', async () => {
      await harness.start();

      const result = await harness.request('POST', '/api/auth/logout');

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('Logged out');
      // The set-cookie header should clear the token (maxAge=0 or expires in past)
      expect(result.setCookie).toContain('token=');
      expect(result.setCookie).toMatch(/max-age=0|expires=/i);
    });
  });

  // ---------------------------------------------------------------
  // POST /api/auth/google
  // ---------------------------------------------------------------
  describe('POST /api/auth/google', () => {
    let fetchSpy;

    beforeEach(() => {
      // Mock fetch only for Google API endpoints; real fetch for local harness
      fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : String(url);
        if (urlStr.includes('googleapis.com') || urlStr.includes('oauth2.googleapis.com')) {
          // Return mock response — will be configured per test
          return Promise.reject(new Error('Google fetch not configured for this test'));
        }
        // Fall through to original fetch for local server requests
        return originalFetch(url, options);
      });
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it('should create a new user via valid Google credential (ID token)', async () => {
      await harness.start();

      const mockInsertedId = '507f1f77bcf86cd799439017';
      mockUsersCollection.findOne.mockResolvedValue(null);
      mockUsersCollection.insertOne.mockResolvedValue({ insertedId: mockInsertedId });
      vi.spyOn(jwt, 'sign').mockReturnValue('google-jwt-token');

      // Mock the fetch to Google tokeninfo endpoint
      fetchSpy.mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : String(url);
        if (urlStr.includes('oauth2.googleapis.com')) {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve({
                email: 'googleuser@gmail.com',
                name: 'Google User',
                picture: 'https://pic.google.com/user.jpg',
              }),
          });
        }
        return originalFetch(url, options);
      });

      const result = await harness.request('POST', '/api/auth/google', {
        credential: 'valid-google-id-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.user).toBeDefined();
      expect(result.body.user.email).toBe('googleuser@gmail.com');
      expect(result.body.user.name).toBe('Google User');
      expect(result.body.user.photoURL).toBe('https://pic.google.com/user.jpg');
      expect(result.body.user.role).toBe('supporter');
      expect(result.body.user.credits).toBe(50);
      expect(result.setCookie).toContain('token=google-jwt-token');

      expect(mockUsersCollection.insertOne).toHaveBeenCalledTimes(1);
      const insertedUser = mockUsersCollection.insertOne.mock.calls[0][0];
      expect(insertedUser.email).toBe('googleuser@gmail.com');
      expect(insertedUser.password).toBe('');
    });

    it('should log in an existing user via valid Google access token', async () => {
      await harness.start();

      const existingUser = {
        _id: '507f1f77bcf86cd799439018',
        name: 'Existing Google User',
        email: 'existinggoogle@gmail.com',
        photoURL: 'https://pic.google.com/existing.jpg',
        password: '',
        role: 'supporter',
        credits: 50,
      };

      mockUsersCollection.findOne.mockResolvedValue(existingUser);
      vi.spyOn(jwt, 'sign').mockReturnValue('google-login-jwt');

      fetchSpy.mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : String(url);
        if (urlStr.includes('googleapis.com')) {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve({
                email: 'existinggoogle@gmail.com',
                name: 'Existing Google User',
                picture: 'https://pic.google.com/existing.jpg',
              }),
          });
        }
        return originalFetch(url, options);
      });

      const result = await harness.request('POST', '/api/auth/google', {
        access_token: 'valid-google-access-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.user.email).toBe('existinggoogle@gmail.com');
      expect(result.body.user.credits).toBe(50);
      expect(result.setCookie).toContain('token=google-login-jwt');

      expect(mockUsersCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should return 400 when both credential and access_token are missing', async () => {
      await harness.start();

      const result = await harness.request('POST', '/api/auth/google', {});

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('required');
    });

    it('should return 400 when Google credential is invalid', async () => {
      await harness.start();

      fetchSpy.mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : String(url);
        if (urlStr.includes('oauth2.googleapis.com')) {
          return Promise.resolve({
            ok: false,
            json: () => Promise.resolve({ error: 'invalid_token' }),
          });
        }
        return originalFetch(url, options);
      });

      const result = await harness.request('POST', '/api/auth/google', {
        credential: 'invalid-google-token',
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid Google credential');
    });

    it('should return 400 when Google access token is invalid', async () => {
      await harness.start();

      fetchSpy.mockImplementation((url, options) => {
        const urlStr = typeof url === 'string' ? url : String(url);
        if (urlStr.includes('googleapis.com')) {
          return Promise.resolve({
            ok: false,
            json: () => Promise.resolve({ error: 'invalid_token' }),
          });
        }
        return originalFetch(url, options);
      });

      const result = await harness.request('POST', '/api/auth/google', {
        access_token: 'invalid-access-token',
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid Google access token');
    });
  });
});
