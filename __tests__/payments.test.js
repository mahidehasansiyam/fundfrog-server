import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import http from 'http';

/**
 * Helper: creates a test Express app with the payment verify route.
 */
function createPaymentsApp(mockPaymentsCollection, mockUsersCollection) {
  const app = express();
  app.use(express.json());

  const INTERNAL_API_KEY = 'test_internal_key';

  // --- POST /api/payments/verify (internal) ---
  app.post('/api/payments/verify', async (req, res) => {
    try {
      const key = req.headers['x-internal-key'];
      if (key !== INTERNAL_API_KEY) {
        return res.status(401).json({ message: 'Unauthorized.' });
      }

      const { stripeSessionId, credits, email, name, amountPaid } = req.body;

      if (!stripeSessionId || !credits || !email || !amountPaid) {
        return res.status(400).json({ message: 'Missing required fields.' });
      }

      await mockPaymentsCollection.insertOne({
        email,
        name,
        creditsPurchased: credits,
        amountPaid,
        stripeSessionId,
        date: new Date(),
      });

      await mockUsersCollection.updateOne({ email }, { $inc: { credits } });

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // Catch-all 404
  app.use((req, res) => {
    res.status(404).json({ message: `Route ${req.originalUrl} not found` });
  });

  return app;
}

/**
 * Helper: starts the app on a random port and makes HTTP requests.
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
        headers: { ...headers },
      };

      if (body !== undefined && typeof body === 'object') {
        if (!options.headers['Content-Type']) {
          options.headers['Content-Type'] = 'application/json';
        }
      }

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
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

describe('Payments API (spec-based)', () => {
  let mockPaymentsCollection;
  let mockUsersCollection;
  let harness;

  beforeEach(() => {
    vi.clearAllMocks();

    mockPaymentsCollection = { insertOne: vi.fn() };
    mockUsersCollection = { updateOne: vi.fn() };

    const app = createPaymentsApp(mockPaymentsCollection, mockUsersCollection);
    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
  });

  describe('POST /api/payments/verify', () => {
    it('should insert payment record and increment user credits', async () => {
      await harness.start();

      const result = await harness.request(
        'POST',
        '/api/payments/verify',
        {
          stripeSessionId: 'cs_test_abc123',
          credits: 100,
          email: 'supporter@example.com',
          name: 'Test Supporter',
          amountPaid: 1000,
        },
        { 'x-internal-key': 'test_internal_key' },
      );

      expect(result.status).toBe(200);
      expect(result.body).toEqual({ success: true });

      expect(mockPaymentsCollection.insertOne).toHaveBeenCalledTimes(1);
      const insertCall = mockPaymentsCollection.insertOne.mock.calls[0][0];
      expect(insertCall.email).toBe('supporter@example.com');
      expect(insertCall.creditsPurchased).toBe(100);
      expect(insertCall.stripeSessionId).toBe('cs_test_abc123');

      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 'supporter@example.com' },
        { $inc: { credits: 100 } },
      );
    });

    it('should handle 300 credit package', async () => {
      await harness.start();

      const result = await harness.request(
        'POST',
        '/api/payments/verify',
        {
          stripeSessionId: 'cs_test_456',
          credits: 300,
          email: 'user@example.com',
          name: 'User',
          amountPaid: 3000,
        },
        { 'x-internal-key': 'test_internal_key' },
      );

      expect(result.status).toBe(200);
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 'user@example.com' },
        { $inc: { credits: 300 } },
      );
    });

    it('should return 401 when x-internal-key is missing', async () => {
      await harness.start();

      const result = await harness.request(
        'POST',
        '/api/payments/verify',
        {
          stripeSessionId: 'cs_test_abc',
          credits: 100,
          email: 'a@b.com',
          name: 'A',
          amountPaid: 1000,
        },
      );

      expect(result.status).toBe(401);
      expect(result.body.message).toBe('Unauthorized.');
      expect(mockPaymentsCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should return 401 when x-internal-key is wrong', async () => {
      await harness.start();

      const result = await harness.request(
        'POST',
        '/api/payments/verify',
        {
          stripeSessionId: 'cs_test_abc',
          credits: 100,
          email: 'a@b.com',
          name: 'A',
          amountPaid: 1000,
        },
        { 'x-internal-key': 'wrong_key' },
      );

      expect(result.status).toBe(401);
    });

    it('should return 400 when required fields are missing', async () => {
      await harness.start();

      const result = await harness.request(
        'POST',
        '/api/payments/verify',
        { credits: 100 },
        { 'x-internal-key': 'test_internal_key' },
      );

      expect(result.status).toBe(400);
      expect(mockPaymentsCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should handle missing name gracefully', async () => {
      await harness.start();

      const result = await harness.request(
        'POST',
        '/api/payments/verify',
        {
          stripeSessionId: 'cs_test_xyz',
          credits: 100,
          email: 'no-name@example.com',
          name: '',
          amountPaid: 1000,
        },
        { 'x-internal-key': 'test_internal_key' },
      );

      expect(result.status).toBe(200);
      expect(mockPaymentsCollection.insertOne).toHaveBeenCalled();
    });
  });

  describe('404 handling', () => {
    it('should return 404 for unknown payment routes', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/payments/unknown');

      expect(result.status).toBe(404);
    });
  });
});
