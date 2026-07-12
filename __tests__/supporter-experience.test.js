import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import http from 'http';
import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongodb';

/**
 * Helper: creates a mock MongoDB cursor with chaining support.
 */
function mockCursor(data) {
  return {
    toArray: vi.fn().mockResolvedValue(data),
    sort: vi.fn().mockReturnThis(),
    skip: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
  };
}

function mockCursorWithCount(data, count) {
  return {
    toArray: vi.fn().mockResolvedValue(data),
    sort: vi.fn().mockReturnThis(),
    skip: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    count: vi.fn().mockResolvedValue(count),
  };
}

/**
 * Helper: creates a test Express app with supporter routes.
 * Routes implement the spec-defined behaviour.
 */
function createSupporterApp(mockContributionsCollection, mockCampaignsCollection, mockUsersCollection) {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  const JWT_SECRET = 'test-secret';

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

  // ── GET /api/supporter/stats ──────────────────────────────────────

  app.get('/api/supporter/stats', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'supporter') {
        return res.status(403).json({ message: 'Access denied. Supporters only.' });
      }

      const allContributions = await mockContributionsCollection
        .find({ supporterEmail: req.user.email })
        .toArray();

      const totalContributions = allContributions.length;
      const pendingCount = allContributions.filter((c) => c.status === 'pending').length;
      const approvedAmount = allContributions
        .filter((c) => c.status === 'approved')
        .reduce((sum, c) => sum + (c.amount || 0), 0);

      return res.json({ stats: { totalContributions, pendingCount, approvedAmount } });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ── GET /api/supporter/approved-contributions ─────────────────────

  app.get('/api/supporter/approved-contributions', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'supporter') {
        return res.status(403).json({ message: 'Access denied. Supporters only.' });
      }

      const approved = await mockContributionsCollection
        .find({ supporterEmail: req.user.email, status: 'approved' })
        .sort({ date: -1 })
        .toArray();

      return res.json({ contributions: approved });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ── POST /api/contributions ───────────────────────────────────────

  app.post('/api/contributions', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'supporter') {
        return res.status(403).json({ message: 'Only supporters can contribute.' });
      }

      const { campaignId, amount } = req.body;
      if (!campaignId || !amount) {
        return res.status(400).json({ message: 'Campaign ID and amount are required.' });
      }

      const campaign = await mockCampaignsCollection.findOne({ _id: new ObjectId(campaignId) });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.status !== 'approved') {
        return res.status(400).json({ message: 'Campaign is not currently accepting contributions.' });
      }

      const contributionAmount = Number(amount);
      if (contributionAmount < campaign.minimumContribution) {
        return res.status(400).json({ message: `Minimum contribution is ${campaign.minimumContribution} credits.` });
      }

      const user = await mockUsersCollection.findOne({ email: req.user.email });
      if (!user || user.credits < contributionAmount) {
        return res.status(400).json({ message: 'Insufficient credits.' });
      }

      await mockUsersCollection.updateOne(
        { email: req.user.email },
        { $inc: { credits: -contributionAmount } },
      );

      const contribution = {
        campaignId,
        campaignTitle: campaign.title,
        amount: contributionAmount,
        supporterEmail: req.user.email,
        supporterName: req.user.name,
        creatorEmail: campaign.creatorEmail,
        creatorName: campaign.creatorName,
        date: new Date(),
        status: 'pending',
      };

      const result = await mockContributionsCollection.insertOne(contribution);
      const saved = { ...contribution, _id: result.insertedId };

      return res.status(201).json({ contribution: saved });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ── GET /api/contributions ────────────────────────────────────────

  app.get('/api/contributions', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'supporter') {
        return res.status(403).json({ message: 'Access denied. Supporters only.' });
      }

      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const skip = (page - 1) * limit;

      const filter = { supporterEmail: req.user.email };

      const total = await mockContributionsCollection.countDocuments(filter);
      const items = await mockContributionsCollection
        .find(filter)
        .sort({ date: -1 })
        .skip(skip)
        .limit(limit)
        .toArray();

      return res.json({
        contributions: items,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      });
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
 * node:http.
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

describe('Supporter Experience API (spec-based)', () => {
  let mockContributionsCollection;
  let mockCampaignsCollection;
  let mockUsersCollection;
  let harness;

  beforeEach(() => {
    vi.clearAllMocks();

    mockContributionsCollection = {
      find: vi.fn(),
      findOne: vi.fn(),
      insertOne: vi.fn(),
      updateOne: vi.fn(),
      countDocuments: vi.fn(),
    };

    mockCampaignsCollection = {
      find: vi.fn(),
      findOne: vi.fn(),
    };

    mockUsersCollection = {
      findOne: vi.fn(),
      updateOne: vi.fn(),
    };

    const app = createSupporterApp(
      mockContributionsCollection,
      mockCampaignsCollection,
      mockUsersCollection,
    );
    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
  });

  // ---------------------------------------------------------------
  // GET /api/supporter/stats
  // ---------------------------------------------------------------
  describe('GET /api/supporter/stats', () => {
    it('should return totalContributions, pendingCount, and approvedAmount for the authenticated supporter', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const mockContributions = [
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign One',
          amount: 500,
          supporterEmail: 'supporter@example.com',
          status: 'approved',
          date: new Date(),
        },
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign Two',
          amount: 250,
          supporterEmail: 'supporter@example.com',
          status: 'pending',
          date: new Date(),
        },
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign Three',
          amount: 100,
          supporterEmail: 'supporter@example.com',
          status: 'approved',
          date: new Date(),
        },
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign Four',
          amount: 50,
          supporterEmail: 'supporter@example.com',
          status: 'rejected',
          date: new Date(),
        },
      ];

      mockContributionsCollection.find.mockReturnValue(mockCursor(mockContributions));

      const result = await harness.request(
        'GET',
        '/api/supporter/stats',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.stats).toBeDefined();
      // total: 4 contributions (all statuses)
      expect(result.body.stats.totalContributions).toBe(4);
      // pending: 1 (Campaign Two)
      expect(result.body.stats.pendingCount).toBe(1);
      // approved amount: 500 + 100 = 600
      expect(result.body.stats.approvedAmount).toBe(600);

      expect(mockContributionsCollection.find).toHaveBeenCalledWith(
        { supporterEmail: 'supporter@example.com' },
      );
    });

    it('should return zeros when the supporter has no contributions', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-456',
        email: 'new-supporter@example.com',
        name: 'New Supporter',
        role: 'supporter',
      });

      mockContributionsCollection.find.mockReturnValue(mockCursor([]));

      const result = await harness.request(
        'GET',
        '/api/supporter/stats',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.stats).toEqual({
        totalContributions: 0,
        pendingCount: 0,
        approvedAmount: 0,
      });
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/supporter/stats');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a supporter (creator role)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const result = await harness.request(
        'GET',
        '/api/supporter/stats',
        undefined,
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Supporters only');
    });

    it('should return 403 when user is an unknown role', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'admin-id',
        email: 'admin@example.com',
        name: 'Admin',
        role: 'admin',
      });

      const result = await harness.request(
        'GET',
        '/api/supporter/stats',
        undefined,
        { Authorization: 'Bearer admin-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Supporters only');
    });
  });

  // ---------------------------------------------------------------
  // GET /api/supporter/approved-contributions
  // ---------------------------------------------------------------
  describe('GET /api/supporter/approved-contributions', () => {
    it('should return approved contributions for the authenticated supporter, sorted by date desc', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const mockApproved = [
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign Two',
          amount: 250,
          supporterEmail: 'supporter@example.com',
          status: 'approved',
          date: new Date('2025-06-15'),
        },
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign One',
          amount: 500,
          supporterEmail: 'supporter@example.com',
          status: 'approved',
          date: new Date('2025-06-01'),
        },
      ];

      const cursor = mockCursor(mockApproved);
      mockContributionsCollection.find.mockReturnValue(cursor);

      const result = await harness.request(
        'GET',
        '/api/supporter/approved-contributions',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toBeDefined();
      expect(result.body.contributions).toHaveLength(2);
      expect(result.body.contributions[0].campaignTitle).toBe('Campaign Two');
      expect(result.body.contributions[1].campaignTitle).toBe('Campaign One');

      expect(mockContributionsCollection.find).toHaveBeenCalledWith({
        supporterEmail: 'supporter@example.com',
        status: 'approved',
      });
      expect(cursor.sort).toHaveBeenCalledWith({ date: -1 });
    });

    it('should return empty array when the supporter has no approved contributions', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-456',
        email: 'supporter-no-approvals@example.com',
        name: 'No Approvals',
        role: 'supporter',
      });

      mockContributionsCollection.find.mockReturnValue(mockCursor([]));

      const result = await harness.request(
        'GET',
        '/api/supporter/approved-contributions',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toEqual([]);
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/supporter/approved-contributions');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const result = await harness.request(
        'GET',
        '/api/supporter/approved-contributions',
        undefined,
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Supporters only');
    });
  });

  // ---------------------------------------------------------------
  // POST /api/contributions
  // ---------------------------------------------------------------
  describe('POST /api/contributions', () => {
    it('should create a pending contribution and deduct credits from the supporter', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Test Campaign',
        story: 'A great campaign',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 50,
        deadline: '2025-12-31',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        status: 'approved',
        amountRaised: 0,
      };

      const mockUser = {
        _id: new ObjectId(),
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
        credits: 500,
      };

      const mockInsertedId = new ObjectId();

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);
      mockUsersCollection.findOne.mockResolvedValue(mockUser);
      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockContributionsCollection.insertOne.mockResolvedValue({ insertedId: mockInsertedId });

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId, amount: 200 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(201);
      expect(result.body.contribution).toBeDefined();
      expect(result.body.contribution.campaignId).toBe(campaignId);
      expect(result.body.contribution.campaignTitle).toBe('Test Campaign');
      expect(result.body.contribution.amount).toBe(200);
      expect(result.body.contribution.supporterEmail).toBe('supporter@example.com');
      expect(result.body.contribution.supporterName).toBe('Test Supporter');
      expect(result.body.contribution.creatorEmail).toBe('creator@example.com');
      expect(result.body.contribution.creatorName).toBe('Test Creator');
      expect(result.body.contribution.status).toBe('pending');
      expect(result.body.contribution.date).toBeDefined();
      expect(result.body.contribution._id).toBeDefined();

      // Verify campaign was found by ID
      expect(mockCampaignsCollection.findOne).toHaveBeenCalledWith(
        { _id: expect.any(ObjectId) },
      );

      // Verify credits were deducted
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 'supporter@example.com' },
        { $inc: { credits: -200 } },
      );

      // Verify contribution was inserted
      expect(mockContributionsCollection.insertOne).toHaveBeenCalledTimes(1);
      const inserted = mockContributionsCollection.insertOne.mock.calls[0][0];
      expect(inserted.status).toBe('pending');
      expect(inserted.amount).toBe(200);
      expect(inserted.campaignId).toBe(campaignId);
    });

    it('should return 400 when amount is below the campaign minimumContribution', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Test Campaign',
        minimumContribution: 100,
        status: 'approved',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
      };

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId, amount: 50 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Minimum contribution is 100');

      // Credits should NOT be deducted
      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
      expect(mockContributionsCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should return 400 when the supporter has insufficient credits', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Test Campaign',
        minimumContribution: 50,
        status: 'approved',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
      };

      const mockUser = {
        _id: new ObjectId(),
        email: 'supporter@example.com',
        credits: 30, // Not enough for 200
      };

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);
      mockUsersCollection.findOne.mockResolvedValue(mockUser);

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId, amount: 200 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Insufficient credits');

      // Credits should NOT be deducted
      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
      expect(mockContributionsCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should return 400 when the supporter has exactly zero credits', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Test Campaign',
        minimumContribution: 50,
        status: 'approved',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
      };

      const mockUser = {
        _id: new ObjectId(),
        email: 'supporter@example.com',
        credits: 0,
      };

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);
      mockUsersCollection.findOne.mockResolvedValue(mockUser);

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId, amount: 50 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Insufficient credits');
    });

    it('should return 403 when the user is a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId: new ObjectId().toString(), amount: 100 },
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only supporters can contribute');
    });

    it('should return 404 when the campaign does not exist', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(null);

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId: new ObjectId().toString(), amount: 100 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Campaign not found');

      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
      expect(mockContributionsCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should return 400 when the campaign is not approved (pending status)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Pending Campaign',
        minimumContribution: 50,
        status: 'pending',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
      };

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId, amount: 100 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('not currently accepting contributions');

      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();
      expect(mockContributionsCollection.insertOne).not.toHaveBeenCalled();
    });

    it('should return 400 when the campaign is rejected', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Rejected Campaign',
        minimumContribution: 50,
        status: 'rejected',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
      };

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId, amount: 100 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('not currently accepting contributions');
    });

    it('should return 400 when campaignId is missing', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { amount: 100 },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Campaign ID and amount are required');
    });

    it('should return 400 when amount is missing', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/contributions',
        { campaignId: new ObjectId().toString() },
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Campaign ID and amount are required');
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('POST', '/api/contributions', {
        campaignId: new ObjectId().toString(),
        amount: 100,
      });

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });
  });

  // ---------------------------------------------------------------
  // GET /api/contributions
  // ---------------------------------------------------------------
  describe('GET /api/contributions', () => {
    it('should return paginated contributions for the authenticated supporter with default pagination', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const mockItems = Array.from({ length: 5 }, (_, i) => ({
        _id: new ObjectId(),
        campaignId: new ObjectId().toString(),
        campaignTitle: `Campaign ${i + 1}`,
        amount: (i + 1) * 100,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Test Supporter',
        status: i % 2 === 0 ? 'approved' : 'pending',
        date: new Date(),
      }));

      mockContributionsCollection.countDocuments.mockResolvedValue(15);
      const cursor = mockCursor(mockItems);
      mockContributionsCollection.find.mockReturnValue(cursor);

      const result = await harness.request(
        'GET',
        '/api/contributions',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toBeDefined();
      expect(result.body.contributions).toHaveLength(5);
      expect(result.body.total).toBe(15);
      expect(result.body.page).toBe(1);
      expect(result.body.totalPages).toBe(2);

      // Verify default pagination values
      expect(mockContributionsCollection.countDocuments).toHaveBeenCalledWith(
        { supporterEmail: 'supporter@example.com' },
      );
      expect(mockContributionsCollection.find).toHaveBeenCalledWith(
        { supporterEmail: 'supporter@example.com' },
      );
      expect(cursor.sort).toHaveBeenCalledWith({ date: -1 });
      expect(cursor.skip).toHaveBeenCalledWith(0);
      expect(cursor.limit).toHaveBeenCalledWith(10);
    });

    it('should respect custom page and limit query parameters', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const mockItems = Array.from({ length: 3 }, (_, i) => ({
        _id: new ObjectId(),
        campaignId: new ObjectId().toString(),
        campaignTitle: `Campaign Page2 ${i + 1}`,
        amount: (i + 1) * 100,
        supporterEmail: 'supporter@example.com',
        status: 'approved',
        date: new Date(),
      }));

      mockContributionsCollection.countDocuments.mockResolvedValue(13);
      const cursor = mockCursor(mockItems);
      mockContributionsCollection.find.mockReturnValue(cursor);

      const result = await harness.request(
        'GET',
        '/api/contributions?page=2&limit=3',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toHaveLength(3);
      expect(result.body.total).toBe(13);
      expect(result.body.page).toBe(2);
      expect(result.body.totalPages).toBe(5); // ceil(13/3) = 5

      expect(cursor.skip).toHaveBeenCalledWith(3); // (page - 1) * limit = 3
      expect(cursor.limit).toHaveBeenCalledWith(3);
    });

    it('should return page 1 even when page param is 0 or negative', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-123',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      mockContributionsCollection.countDocuments.mockResolvedValue(5);
      const cursor = mockCursor([]);
      mockContributionsCollection.find.mockReturnValue(cursor);

      // page=0 should fall back to 1
      const result = await harness.request(
        'GET',
        '/api/contributions?page=0',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.page).toBe(1);
      expect(cursor.skip).toHaveBeenCalledWith(0);
    });

    it('should return empty contributions array when no contributions exist', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id-456',
        email: 'empty-supporter@example.com',
        name: 'Empty Supporter',
        role: 'supporter',
      });

      mockContributionsCollection.countDocuments.mockResolvedValue(0);
      mockContributionsCollection.find.mockReturnValue(mockCursor([]));

      const result = await harness.request(
        'GET',
        '/api/contributions',
        undefined,
        { Authorization: 'Bearer supporter-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toEqual([]);
      expect(result.body.total).toBe(0);
      expect(result.body.page).toBe(1);
      expect(result.body.totalPages).toBe(0);
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/contributions');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a supporter', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const result = await harness.request(
        'GET',
        '/api/contributions',
        undefined,
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Supporters only');
    });
  });
});
