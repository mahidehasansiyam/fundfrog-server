import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import http from 'http';
import jwt from 'jsonwebtoken';

/**
 * Helper: creates a test Express app with Stripe payment routes.
 * Routes implement the spec-defined behaviour — no implementation details.
 */
function createPaymentsApp(mockPaymentsCollection, mockUsersCollection, mockStripe) {
  const app = express();
  const JWT_SECRET = 'test-secret';

  // -----------------------------------------------------------------------
  // POST /api/payments/webhook — public, MUST use express.raw() to preserve
  // Stripe's signature. Registered BEFORE global express.json().
  // -----------------------------------------------------------------------
  app.post(
    '/api/payments/webhook',
    express.raw({ type: 'application/json' }),
    async (req, res) => {
      try {
        const sig = req.headers['stripe-signature'];
        const endpointSecret =
          process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test';

        // Verify signature — throws on invalid signature
        const event = mockStripe.webhooks.constructEvent(
          req.body,
          sig,
          endpointSecret,
        );

        // Only process checkout.session.completed events
        if (event.type === 'checkout.session.completed') {
          const session = event.data.object;
          const { credits, email, name } = session.metadata;

          // Insert payment record
          await mockPaymentsCollection.insertOne({
            email,
            name: name || '',
            creditsPurchased: Number(credits),
            amountPaid: session.amount_total,
            stripeSessionId: session.id,
            date: new Date(),
          });

          // Increment user credits atomically
          await mockUsersCollection.updateOne(
            { email },
            { $inc: { credits: Number(credits) } },
          );
        }

        // Acknowledge receipt to Stripe
        return res.json({ received: true });
      } catch (err) {
        return res.status(400).json({ message: 'Invalid signature.' });
      }
    },
  );

  // -----------------------------------------------------------------------
  // Global middleware for all other routes
  // -----------------------------------------------------------------------
  app.use(express.json());
  app.use(cookieParser());

  // -----------------------------------------------------------------------
  // verifyToken middleware — reads from Bearer header or cookie
  // -----------------------------------------------------------------------
  function verifyToken(req, res, next) {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
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

  function requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
      }
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ message: `Access denied. Required role: ${roles.join(' or ')}.` });
      }
      next();
    };
  }

  // -----------------------------------------------------------------------
  // POST /api/payments/create-checkout — supporter only (verifyToken)
  // -----------------------------------------------------------------------
  app.post('/api/payments/create-checkout', verifyToken, requireRole('supporter'), async (req, res) => {
    try {

      const { credits } = req.body;

      // Validate credits field is present
      if (credits === undefined || credits === null) {
        return res.status(400).json({ message: 'Credits amount is required.' });
      }

      // Validate credits is one of the 4 defined package sizes
      const validPackages = [100, 300, 800, 1500];
      if (!validPackages.includes(Number(credits))) {
        return res.status(400).json({ message: 'Invalid credit package.' });
      }

      // Create Stripe Checkout Session
      const session = await mockStripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: `${credits} Credits` },
              unit_amount: credits * 10, // 1 credit = 10 cents
            },
            quantity: 1,
          },
        ],
        mode: 'payment',
        success_url:
          'http://localhost:3000/dashboard/supporter?payment=success',
        cancel_url:
          'http://localhost:3000/dashboard/supporter/purchase-credit?payment=cancelled',
        client_reference_id: req.user.id,
        metadata: {
          credits: String(credits),
          email: req.user.email,
          name: req.user.name,
        },
      });

      return res.json({ url: session.url });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // Catch-all 404
  app.use((req, res) => {
    res.status(404).json({ message: `Route ${req.originalUrl} not found` });
  });

  return app;
}

/**
 * Helper: starts the app on a random port and makes requests using
 * node:http (so we don't collide with global fetch mocks).
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
            resolve({ status: res.statusCode, body: parsed });
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

// =========================================================================
// Tests
// =========================================================================

describe('Payments API — Stripe (spec-based)', () => {
  let mockPaymentsCollection;
  let mockUsersCollection;
  let mockStripe;
  let harness;

  beforeEach(() => {
    vi.clearAllMocks();

    // Set webhook secret for tests
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';

    mockPaymentsCollection = {
      insertOne: vi.fn(),
    };

    mockUsersCollection = {
      updateOne: vi.fn(),
    };

    mockStripe = {
      checkout: {
        sessions: {
          create: vi.fn(),
        },
      },
      webhooks: {
        constructEvent: vi.fn(),
      },
    };

    const app = createPaymentsApp(
      mockPaymentsCollection,
      mockUsersCollection,
      mockStripe,
    );
    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
    delete process.env.STRIPE_WEBHOOK_SECRET;
  });

  // -----------------------------------------------------------------------
  // POST /api/payments/create-checkout
  // -----------------------------------------------------------------------
  describe('POST /api/payments/create-checkout', () => {
    // ---------- Auth guard tests ----------

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('POST', '/api/payments/create-checkout', {
        credits: 100,
      });

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 401 when an invalid token is provided', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new Error('jwt malformed');
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 100 },
        { Authorization: 'Bearer invalid-jwt-token' },
      );

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Invalid token');
    });

    // ---------- Role guard tests ----------

    it('should return 403 when user is a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 100 },
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Required role: supporter');
    });

    it('should return 403 when user is an admin', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'admin-id-456',
        email: 'admin@example.com',
        name: 'Test Admin',
        role: 'admin',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 100 },
        { Authorization: 'Bearer admin-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Required role: supporter');
    });

    // ---------- Validation tests ----------

    it('should return 400 when credits field is missing', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        {},
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('required');
    });

    it('should return 400 when credits is null', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: null },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('required');
    });

    it('should return 400 for invalid credit package (200)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 200 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid credit package');
    });

    it('should return 400 for invalid credit package (0)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 0 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid credit package');
    });

    it('should return 400 for negative credits', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: -100 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Invalid credit package');
    });

    // ---------- Success tests for all 4 packages ----------

    it('should create a Stripe Checkout Session for 100 credits and return the URL', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockStripe.checkout.sessions.create.mockResolvedValue({
        id: 'cs_test_100credits',
        url: 'https://checkout.stripe.com/c/pay/cs_test_100credits',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 100 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.url).toBe(
        'https://checkout.stripe.com/c/pay/cs_test_100credits',
      );
    });

    it('should create a Stripe Checkout Session for 300 credits and return the URL', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockStripe.checkout.sessions.create.mockResolvedValue({
        id: 'cs_test_300credits',
        url: 'https://checkout.stripe.com/c/pay/cs_test_300credits',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 300 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.url).toBe(
        'https://checkout.stripe.com/c/pay/cs_test_300credits',
      );
    });

    it('should create a Stripe Checkout Session for 800 credits and return the URL', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockStripe.checkout.sessions.create.mockResolvedValue({
        id: 'cs_test_800credits',
        url: 'https://checkout.stripe.com/c/pay/cs_test_800credits',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 800 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.url).toBe(
        'https://checkout.stripe.com/c/pay/cs_test_800credits',
      );
    });

    it('should create a Stripe Checkout Session for 1500 credits and return the URL', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockStripe.checkout.sessions.create.mockResolvedValue({
        id: 'cs_test_1500credits',
        url: 'https://checkout.stripe.com/c/pay/cs_test_1500credits',
      });

      const result = await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 1500 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.url).toBe(
        'https://checkout.stripe.com/c/pay/cs_test_1500credits',
      );
    });

    // ---------- Stripe session params verification ----------

    it('should call stripe.checkout.sessions.create with the correct parameters for 100 credits', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-789',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockStripe.checkout.sessions.create.mockResolvedValue({
        id: 'cs_test_params',
        url: 'https://checkout.stripe.com/c/pay/cs_test_params',
      });

      await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 100 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(mockStripe.checkout.sessions.create).toHaveBeenCalledTimes(1);
      expect(mockStripe.checkout.sessions.create).toHaveBeenCalledWith({
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: '100 Credits' },
              unit_amount: 1000, // 100 credits * 10 cents
            },
            quantity: 1,
          },
        ],
        mode: 'payment',
        success_url:
          'http://localhost:3000/dashboard/supporter?payment=success',
        cancel_url:
          'http://localhost:3000/dashboard/supporter/purchase-credit?payment=cancelled',
        client_reference_id: 'supporter-id-789',
        metadata: {
          credits: '100',
          email: 'supporter@example.com',
          name: 'Test Supporter',
        },
      });
    });

    it('should call stripe.checkout.sessions.create with correct client_reference_id from token', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'custom-user-id-abc',
        email: 'user@test.com',
        name: 'Custom User',
        role: 'supporter',
      });

      mockStripe.checkout.sessions.create.mockResolvedValue({
        id: 'cs_test_crid',
        url: 'https://checkout.stripe.com/c/pay/test',
      });

      await harness.request(
        'POST',
        '/api/payments/create-checkout',
        { credits: 300 },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(mockStripe.checkout.sessions.create).toHaveBeenCalledWith(
        expect.objectContaining({
          client_reference_id: 'custom-user-id-abc',
        }),
      );
    });

    it('should calculate correct unit_amount for each credit package', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id',
        email: 's@test.com',
        name: 'S',
        role: 'supporter',
      });

      const packages = [
        { credits: 100, expectedUnitAmount: 1000 },
        { credits: 300, expectedUnitAmount: 3000 },
        { credits: 800, expectedUnitAmount: 8000 },
        { credits: 1500, expectedUnitAmount: 15000 },
      ];

      for (const pkg of packages) {
        mockStripe.checkout.sessions.create.mockResolvedValue({
          id: `cs_test_${pkg.credits}`,
          url: `https://checkout.stripe.com/c/pay/test_${pkg.credits}`,
        });

        await harness.request(
          'POST',
          '/api/payments/create-checkout',
          { credits: pkg.credits },
          { Authorization: 'Bearer supporter-jwt' },
        );

        expect(mockStripe.checkout.sessions.create).toHaveBeenLastCalledWith(
          expect.objectContaining({
            line_items: [
              expect.objectContaining({
                price_data: expect.objectContaining({
                  unit_amount: pkg.expectedUnitAmount,
                }),
              }),
            ],
          }),
        );
      }
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/payments/webhook
  // -----------------------------------------------------------------------
  describe('POST /api/payments/webhook', () => {
    // ---------- Success: checkout.session.completed ----------

    it('should process checkout.session.completed event and insert payment record', async () => {
      await harness.start();

      const mockEvent = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_completed_123',
            amount_total: 1000, // $10 in cents
            metadata: {
              credits: '100',
              email: 'supporter@example.com',
              name: 'Test Supporter',
            },
          },
        },
      };

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent);

      const result = await harness.request(
        'POST',
        '/api/payments/webhook',
        mockEvent,
        { 'stripe-signature': 'valid_sig_123' },
      );

      expect(result.status).toBe(200);
      expect(result.body.received).toBe(true);

      // Verify payment record inserted
      expect(mockPaymentsCollection.insertOne).toHaveBeenCalledTimes(1);
      const insertedPayment = mockPaymentsCollection.insertOne.mock.calls[0][0];
      expect(insertedPayment.email).toBe('supporter@example.com');
      expect(insertedPayment.name).toBe('Test Supporter');
      expect(insertedPayment.creditsPurchased).toBe(100);
      expect(insertedPayment.amountPaid).toBe(1000);
      expect(insertedPayment.stripeSessionId).toBe('cs_test_completed_123');
      expect(insertedPayment.date).toBeInstanceOf(Date);

      // Verify user credits incremented
      expect(mockUsersCollection.updateOne).toHaveBeenCalledTimes(1);
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 'supporter@example.com' },
        { $inc: { credits: 100 } },
      );
    });

    it('should process 300 credit package webhook and increment correct credits', async () => {
      await harness.start();

      const mockEvent = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_300_completed',
            amount_total: 3000,
            metadata: {
              credits: '300',
              email: 'big-supporter@example.com',
              name: 'Big Spender',
            },
          },
        },
      };

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent);

      await harness.request(
        'POST',
        '/api/payments/webhook',
        mockEvent,
        { 'stripe-signature': 'valid_sig_456' },
      );

      expect(mockPaymentsCollection.insertOne).toHaveBeenCalledTimes(1);
      expect(
        mockPaymentsCollection.insertOne.mock.calls[0][0].creditsPurchased,
      ).toBe(300);

      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 'big-supporter@example.com' },
        { $inc: { credits: 300 } },
      );
    });

    it('should handle missing name in session metadata gracefully', async () => {
      await harness.start();

      const mockEvent = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_noname',
            amount_total: 1000,
            metadata: {
              credits: '100',
              email: 'no-name@example.com',
              // name intentionally omitted
            },
          },
        },
      };

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent);

      await harness.request(
        'POST',
        '/api/payments/webhook',
        mockEvent,
        { 'stripe-signature': 'valid_sig' },
      );

      expect(mockPaymentsCollection.insertOne).toHaveBeenCalledTimes(1);
      const inserted = mockPaymentsCollection.insertOne.mock.calls[0][0];
      expect(inserted.name).toBe('');
    });

    // ---------- Signature verification errors ----------

    it('should return 400 when stripe-signature header is invalid', async () => {
      await harness.start();

      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Invalid signature');
      });

      const result = await harness.request(
        'POST',
        '/api/payments/webhook',
        {
          type: 'checkout.session.completed',
          data: { object: { id: 'cs_test_badsig', metadata: {} } },
        },
        { 'stripe-signature': 'bad_signature' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toBe('Invalid signature.');
      expect(mockPaymentsCollection.insertOne).not.toHaveBeenCalled();
      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
    });

    it('should return 400 when stripe-signature header is missing', async () => {
      await harness.start();

      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('No signatures found');
      });

      const result = await harness.request(
        'POST',
        '/api/payments/webhook',
        { type: 'checkout.session.completed', data: { object: {} } },
        // No stripe-signature header
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toBe('Invalid signature.');
      expect(mockPaymentsCollection.insertOne).not.toHaveBeenCalled();
    });

    // ---------- Non-relevant events ----------

    it('should return 200 for non-checkout.session.completed events without processing', async () => {
      await harness.start();

      const mockEvent = {
        type: 'checkout.session.expired',
        data: {
          object: {
            id: 'cs_test_expired',
            metadata: { credits: '100', email: 'test@example.com' },
          },
        },
      };

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent);

      const result = await harness.request(
        'POST',
        '/api/payments/webhook',
        mockEvent,
        { 'stripe-signature': 'valid_sig' },
      );

      // Must return 200 to acknowledge receipt
      expect(result.status).toBe(200);
      expect(result.body.received).toBe(true);

      // Must NOT insert payment or increment credits
      expect(mockPaymentsCollection.insertOne).not.toHaveBeenCalled();
      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
    });

    it('should return 200 for payment_intent.succeeded events without processing', async () => {
      await harness.start();

      const mockEvent = {
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: 'pi_test_succeeded',
          },
        },
      };

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent);

      const result = await harness.request(
        'POST',
        '/api/payments/webhook',
        mockEvent,
        { 'stripe-signature': 'valid_sig' },
      );

      expect(result.status).toBe(200);
      expect(mockPaymentsCollection.insertOne).not.toHaveBeenCalled();
      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
    });

    // ---------- Webhook signature verification params ----------

    it('should call constructEvent with raw body, signature header, and endpoint secret', async () => {
      await harness.start();

      const mockEvent = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_sigcheck',
            amount_total: 1000,
            metadata: { credits: '100', email: 'a@b.com', name: 'A' },
          },
        },
      };

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent);

      await harness.request(
        'POST',
        '/api/payments/webhook',
        mockEvent,
        { 'stripe-signature': 't=123,v1=signature_value' },
      );

      // constructEvent should have been called — we can't assert on the raw
      // buffer easily, but we can verify it was invoked with the sig and secret
      expect(mockStripe.webhooks.constructEvent).toHaveBeenCalledWith(
        expect.any(Buffer), // raw body buffer
        't=123,v1=signature_value',
        'whsec_test',
      );
    });
  });

  // -----------------------------------------------------------------------
  // 404 handling
  // -----------------------------------------------------------------------
  describe('404 handling', () => {
    it('should return 404 for unknown payment routes', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/payments/unknown');

      expect(result.status).toBe(404);
    });

    it('should return 404 for GET /api/payments/create-checkout (POST only)', async () => {
      await harness.start();

      const result = await harness.request(
        'GET',
        '/api/payments/create-checkout',
      );

      expect(result.status).toBe(404);
    });

    it('should return 404 for GET /api/payments/webhook (POST only)', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/payments/webhook');

      expect(result.status).toBe(404);
    });
  });
});
