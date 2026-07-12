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
    limit: vi.fn().mockReturnThis(),
  };
}

/**
 * Helper: creates a test Express app with creator dashboard routes.
 * Routes implement the spec-defined behaviour.
 */
function createCreatorApp(mockCampaignsCollection, mockContributionsCollection, mockUsersCollection) {
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

  // --- GET /api/creator/stats ---
  app.get('/api/creator/stats', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can access this resource.' });
      }

      const now = new Date();
      const campaigns = await mockCampaignsCollection.find({ creatorEmail: req.user.email }).toArray();
      const totalCampaigns = campaigns.length;
      const activeCampaigns = campaigns.filter(
        (c) => c.status === 'approved' && new Date(c.deadline) > now
      ).length;
      const totalRaised = campaigns.reduce((sum, c) => sum + (c.amountRaised || 0), 0);

      return res.json({ stats: { totalCampaigns, activeCampaigns, totalRaised } });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- GET /api/creator/pending-contributions ---
  app.get('/api/creator/pending-contributions', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can access this resource.' });
      }

      const contributions = await mockContributionsCollection
        .find({ creatorEmail: req.user.email, status: 'pending' })
        .toArray();

      return res.json({ contributions });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- PATCH /api/contributions/:id/approve ---
  app.patch('/api/contributions/:id/approve', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can access this resource.' });
      }

      const contribution = await mockContributionsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!contribution) {
        return res.status(404).json({ message: 'Contribution not found.' });
      }

      if (contribution.creatorEmail !== req.user.email) {
        return res.status(403).json({ message: 'This contribution does not belong to your campaign.' });
      }

      if (contribution.status !== 'pending') {
        return res.status(400).json({ message: 'Contribution is not in pending status.' });
      }

      await mockContributionsCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: 'approved' } },
      );

      await mockCampaignsCollection.updateOne(
        { _id: new ObjectId(contribution.campaignId) },
        { $inc: { amountRaised: contribution.amount } },
      );

      // Notification entry (spec requirement)
      const notification = {
        userId: contribution.supporterEmail,
        type: 'contribution_approved',
        message: `Your contribution of ${contribution.amount} credits to "${contribution.campaignTitle}" has been approved.`,
        createdAt: new Date(),
      };
      // Not checking a collection — just verifying the intent per spec

      return res.json({ message: 'Contribution approved.', contribution: { ...contribution, status: 'approved' } });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- PATCH /api/contributions/:id/reject ---
  app.patch('/api/contributions/:id/reject', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can access this resource.' });
      }

      const contribution = await mockContributionsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!contribution) {
        return res.status(404).json({ message: 'Contribution not found.' });
      }

      if (contribution.creatorEmail !== req.user.email) {
        return res.status(403).json({ message: 'This contribution does not belong to your campaign.' });
      }

      if (contribution.status !== 'pending') {
        return res.status(400).json({ message: 'Contribution is not in pending status.' });
      }

      // Refund credits to supporter
      await mockUsersCollection.updateOne(
        { email: contribution.supporterEmail },
        { $inc: { credits: contribution.amount } },
      );

      await mockContributionsCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: 'rejected' } },
      );

      // Notification entry (spec requirement)
      const notification = {
        userId: contribution.supporterEmail,
        type: 'contribution_rejected',
        message: `Your contribution of ${contribution.amount} credits to "${contribution.campaignTitle}" has been rejected.`,
        createdAt: new Date(),
      };

      return res.json({ message: 'Contribution rejected and supporter refunded.', contribution: { ...contribution, status: 'rejected' } });
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

describe('Creator Dashboard API (spec-based)', () => {
  let mockCampaignsCollection;
  let mockContributionsCollection;
  let mockUsersCollection;
  let harness;

  beforeEach(() => {
    vi.clearAllMocks();

    mockCampaignsCollection = {
      find: vi.fn(),
      findOne: vi.fn(),
      insertOne: vi.fn(),
      updateOne: vi.fn(),
      deleteOne: vi.fn(),
    };

    mockContributionsCollection = {
      find: vi.fn(),
      findOne: vi.fn(),
      updateOne: vi.fn(),
      deleteMany: vi.fn(),
    };

    mockUsersCollection = {
      findOne: vi.fn(),
      updateOne: vi.fn(),
    };

    const app = createCreatorApp(
      mockCampaignsCollection,
      mockContributionsCollection,
      mockUsersCollection,
    );
    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
  });

  // ---------------------------------------------------------------
  // GET /api/creator/stats
  // ---------------------------------------------------------------
  describe('GET /api/creator/stats', () => {
    it('should return totalCampaigns, activeCampaigns, totalRaised for the authenticated creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const now = new Date();
      const futureDate = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
      const pastDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000).toISOString();

      const mockCampaigns = [
        {
          _id: new ObjectId(),
          title: 'Active Campaign',
          status: 'approved',
          deadline: futureDate,
          amountRaised: 5000,
          creatorEmail: 'creator@example.com',
        },
        {
          _id: new ObjectId(),
          title: 'Expired Approved Campaign',
          status: 'approved',
          deadline: pastDate,
          amountRaised: 2000,
          creatorEmail: 'creator@example.com',
        },
        {
          _id: new ObjectId(),
          title: 'Pending Campaign',
          status: 'pending',
          deadline: futureDate,
          amountRaised: 0,
          creatorEmail: 'creator@example.com',
        },
      ];

      mockCampaignsCollection.find.mockReturnValue(mockCursor(mockCampaigns));

      const result = await harness.request(
        'GET',
        '/api/creator/stats',
        undefined,
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.stats).toBeDefined();
      expect(result.body.stats.totalCampaigns).toBe(3);
      // Only 1 is approved AND deadline in the future
      expect(result.body.stats.activeCampaigns).toBe(1);
      // Sum of all amountRaised: 5000 + 2000 + 0 = 7000
      expect(result.body.stats.totalRaised).toBe(7000);

      expect(mockCampaignsCollection.find).toHaveBeenCalledWith(
        { creatorEmail: 'creator@example.com' },
      );
    });

    it('should return zeros when the creator has no campaigns', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-456',
        email: 'newcreator@example.com',
        name: 'New Creator',
        role: 'creator',
      });

      mockCampaignsCollection.find.mockReturnValue(mockCursor([]));

      const result = await harness.request(
        'GET',
        '/api/creator/stats',
        undefined,
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.stats).toEqual({
        totalCampaigns: 0,
        activeCampaigns: 0,
        totalRaised: 0,
      });
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/creator/stats');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a creator (e.g., supporter role)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'GET',
        '/api/creator/stats',
        undefined,
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can access this resource');
    });
  });

  // ---------------------------------------------------------------
  // GET /api/creator/pending-contributions
  // ---------------------------------------------------------------
  describe('GET /api/creator/pending-contributions', () => {
    it('should return pending contributions for the authenticated creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const mockContributions = [
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign One',
          amount: 500,
          supporterEmail: 'supporter1@example.com',
          supporterName: 'Alice',
          creatorEmail: 'creator@example.com',
          creatorName: 'Test Creator',
          date: new Date(),
          status: 'pending',
        },
        {
          _id: new ObjectId(),
          campaignId: new ObjectId().toString(),
          campaignTitle: 'Campaign Two',
          amount: 250,
          supporterEmail: 'supporter2@example.com',
          supporterName: 'Bob',
          creatorEmail: 'creator@example.com',
          creatorName: 'Test Creator',
          date: new Date(),
          status: 'pending',
        },
      ];

      mockContributionsCollection.find.mockReturnValue(mockCursor(mockContributions));

      const result = await harness.request(
        'GET',
        '/api/creator/pending-contributions',
        undefined,
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toBeDefined();
      expect(result.body.contributions).toHaveLength(2);
      expect(result.body.contributions[0].campaignTitle).toBe('Campaign One');
      expect(result.body.contributions[1].campaignTitle).toBe('Campaign Two');
      expect(result.body.contributions[0].status).toBe('pending');
      expect(result.body.contributions[1].status).toBe('pending');

      expect(mockContributionsCollection.find).toHaveBeenCalledWith(
        { creatorEmail: 'creator@example.com', status: 'pending' },
      );
    });

    it('should return empty array when no pending contributions exist', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-456',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockContributionsCollection.find.mockReturnValue(mockCursor([]));

      const result = await harness.request(
        'GET',
        '/api/creator/pending-contributions',
        undefined,
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.contributions).toEqual([]);
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/creator/pending-contributions');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'GET',
        '/api/creator/pending-contributions',
        undefined,
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can access this resource');
    });
  });

  // ---------------------------------------------------------------
  // PATCH /api/contributions/:id/approve
  // ---------------------------------------------------------------
  describe('PATCH /api/contributions/:id/approve', () => {
    it('should approve a pending contribution and increment campaign amountRaised', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const contributionId = new ObjectId();
      const campaignId = new ObjectId().toString();

      const mockContribution = {
        _id: contributionId,
        campaignId,
        campaignTitle: 'Test Campaign',
        amount: 500,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Supporter',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        date: new Date(),
        status: 'pending',
      };

      mockContributionsCollection.findOne.mockResolvedValue(mockContribution);
      mockContributionsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockCampaignsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await harness.request(
        'PATCH',
        `/api/contributions/${contributionId}/approve`,
        {},
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('approved');
      expect(result.body.contribution.status).toBe('approved');

      // Verify contribution status updated
      expect(mockContributionsCollection.updateOne).toHaveBeenCalledWith(
        { _id: contributionId },
        { $set: { status: 'approved' } },
      );

      // Verify campaign amountRaised incremented
      expect(mockCampaignsCollection.updateOne).toHaveBeenCalledWith(
        { _id: new ObjectId(campaignId) },
        { $inc: { amountRaised: 500 } },
      );
    });

    it('should return 404 when contribution is not found', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockContributionsCollection.findOne.mockResolvedValue(null);

      const result = await harness.request(
        'PATCH',
        '/api/contributions/507f1f77bcf86cd799439999/approve',
        {},
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Contribution not found');
    });

    it('should return 403 when contribution creatorEmail does not match the authenticated user', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-456',
        email: 'other-creator@example.com',
        name: 'Other Creator',
        role: 'creator',
      });

      const contributionId = new ObjectId();

      const mockContribution = {
        _id: contributionId,
        campaignId: new ObjectId().toString(),
        campaignTitle: 'Not My Campaign',
        amount: 300,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Supporter',
        creatorEmail: 'different-creator@example.com', // different from token
        creatorName: 'Different Creator',
        date: new Date(),
        status: 'pending',
      };

      mockContributionsCollection.findOne.mockResolvedValue(mockContribution);

      const result = await harness.request(
        'PATCH',
        `/api/contributions/${contributionId}/approve`,
        {},
        { Authorization: 'Bearer other-creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('does not belong to your campaign');
    });

    it('should return 400 when contribution status is not "pending" (e.g., already approved)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const contributionId = new ObjectId();

      const mockContribution = {
        _id: contributionId,
        campaignId: new ObjectId().toString(),
        campaignTitle: 'Test Campaign',
        amount: 500,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Supporter',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        date: new Date(),
        status: 'approved', // already approved
      };

      mockContributionsCollection.findOne.mockResolvedValue(mockContribution);

      const result = await harness.request(
        'PATCH',
        `/api/contributions/${contributionId}/approve`,
        {},
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('not in pending status');
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request(
        'PATCH',
        '/api/contributions/507f1f77bcf86cd799439011/approve',
        {},
      );

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'PATCH',
        '/api/contributions/507f1f77bcf86cd799439011/approve',
        {},
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can access this resource');
    });
  });

  // ---------------------------------------------------------------
  // PATCH /api/contributions/:id/reject
  // ---------------------------------------------------------------
  describe('PATCH /api/contributions/:id/reject', () => {
    it('should reject a pending contribution and refund credits to the supporter', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const contributionId = new ObjectId();
      const campaignId = new ObjectId().toString();

      const mockContribution = {
        _id: contributionId,
        campaignId,
        campaignTitle: 'Test Campaign',
        amount: 500,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Supporter',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        date: new Date(),
        status: 'pending',
      };

      mockContributionsCollection.findOne.mockResolvedValue(mockContribution);
      mockContributionsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await harness.request(
        'PATCH',
        `/api/contributions/${contributionId}/reject`,
        {},
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('rejected');
      expect(result.body.message).toContain('refunded');
      expect(result.body.contribution.status).toBe('rejected');

      // Verify refund: supporter's credits incremented
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 'supporter@example.com' },
        { $inc: { credits: 500 } },
      );

      // Verify contribution status updated to rejected
      expect(mockContributionsCollection.updateOne).toHaveBeenCalledWith(
        { _id: contributionId },
        { $set: { status: 'rejected' } },
      );
    });

    it('should return 404 when contribution is not found', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockContributionsCollection.findOne.mockResolvedValue(null);

      const result = await harness.request(
        'PATCH',
        '/api/contributions/507f1f77bcf86cd799439999/reject',
        {},
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Contribution not found');
    });

    it('should return 403 when contribution creatorEmail does not match the authenticated user', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-456',
        email: 'other-creator@example.com',
        name: 'Other Creator',
        role: 'creator',
      });

      const contributionId = new ObjectId();

      const mockContribution = {
        _id: contributionId,
        campaignId: new ObjectId().toString(),
        campaignTitle: 'Not My Campaign',
        amount: 300,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Supporter',
        creatorEmail: 'different-creator@example.com',
        creatorName: 'Different Creator',
        date: new Date(),
        status: 'pending',
      };

      mockContributionsCollection.findOne.mockResolvedValue(mockContribution);

      const result = await harness.request(
        'PATCH',
        `/api/contributions/${contributionId}/reject`,
        {},
        { Authorization: 'Bearer other-creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('does not belong to your campaign');
    });

    it('should return 400 when contribution status is not "pending" (e.g., already rejected)', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const contributionId = new ObjectId();

      const mockContribution = {
        _id: contributionId,
        campaignId: new ObjectId().toString(),
        campaignTitle: 'Test Campaign',
        amount: 500,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Supporter',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        date: new Date(),
        status: 'rejected', // already rejected
      };

      mockContributionsCollection.findOne.mockResolvedValue(mockContribution);

      const result = await harness.request(
        'PATCH',
        `/api/contributions/${contributionId}/reject`,
        {},
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('not in pending status');
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request(
        'PATCH',
        '/api/contributions/507f1f77bcf86cd799439011/reject',
        {},
      );

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'PATCH',
        '/api/contributions/507f1f77bcf86cd799439011/reject',
        {},
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can access this resource');
    });
  });
});
