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
 * Helper: creates a test Express app with campaign routes.
 * Routes implement the spec-defined behaviour.
 */
function createCampaignsApp(mockCampaignsCollection, mockUsersCollection, mockContributionsCollection) {
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

  // --- GET /api/campaigns (public) ---
  app.get('/api/campaigns', async (req, res) => {
    try {
      const { category, status, search } = req.query;
      const filter = {};

      if (category) filter.category = category;
      filter.status = status || 'approved';

      if (search) {
        filter.title = { $regex: search, $options: 'i' };
      }

      let cursor = mockCampaignsCollection.find(filter);

      if (req.query['top-funded']) {
        cursor = cursor.sort({ amountRaised: -1 }).limit(6);
      }

      const results = await cursor.toArray();
      return res.json({ campaigns: results });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- GET /api/campaigns/:id (public) ---
  app.get('/api/campaigns/:id', async (req, res) => {
    try {
      const campaign = await mockCampaignsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      return res.json({ campaign });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- POST /api/campaigns (creator only) ---
  app.post('/api/campaigns', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can create campaigns.' });
      }

      const { title, story, category, fundingGoal, minimumContribution, deadline, rewardInfo, imageURL } = req.body;

      if (!title || !story || !category || !fundingGoal || !minimumContribution || !deadline) {
        return res.status(400).json({ message: 'Title, story, category, funding goal, minimum contribution, and deadline are required.' });
      }

      const campaign = {
        title,
        story,
        category,
        fundingGoal: Number(fundingGoal),
        minimumContribution: Number(minimumContribution),
        deadline,
        rewardInfo: rewardInfo || '',
        imageURL: imageURL || '',
        creatorEmail: req.user.email,
        creatorName: req.user.name,
        amountRaised: 0,
        status: 'pending',
        createdAt: new Date(),
      };

      const result = await mockCampaignsCollection.insertOne(campaign);
      const saved = { ...campaign, _id: result.insertedId };
      return res.status(201).json({ campaign: saved });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- PUT /api/campaigns/:id (creator owner only) ---
  app.put('/api/campaigns/:id', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can update campaigns.' });
      }

      const campaign = await mockCampaignsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.creatorEmail !== req.user.email) {
        return res.status(403).json({ message: 'You can only update your own campaigns.' });
      }

      const { title, story, rewardInfo } = req.body;
      const update = {};
      if (title !== undefined) update.title = title;
      if (story !== undefined) update.story = story;
      if (rewardInfo !== undefined) update.rewardInfo = rewardInfo;

      if (Object.keys(update).length === 0) {
        return res.status(400).json({ message: 'At least one field (title, story, reward_info) must be provided.' });
      }

      await mockCampaignsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
      const updated = await mockCampaignsCollection.findOne({ _id: new ObjectId(req.params.id) });

      return res.json({ campaign: updated });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // --- DELETE /api/campaigns/:id (creator owner only) ---
  app.delete('/api/campaigns/:id', verifyToken, async (req, res) => {
    try {
      if (req.user.role !== 'creator') {
        return res.status(403).json({ message: 'Only creators can delete campaigns.' });
      }

      const campaign = await mockCampaignsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.creatorEmail !== req.user.email) {
        return res.status(403).json({ message: 'You can only delete your own campaigns.' });
      }

      // Refund all approved supporters
      const approvedContributions = await mockContributionsCollection
        .find({ campaignId: req.params.id, status: 'approved' })
        .toArray();

      for (const c of approvedContributions) {
        await mockUsersCollection.updateOne(
          { email: c.supporterEmail },
          { $inc: { credits: c.amount } },
        );
      }

      await mockContributionsCollection.deleteMany({ campaignId: req.params.id });
      await mockCampaignsCollection.deleteOne({ _id: new ObjectId(req.params.id) });

      return res.json({ message: 'Campaign deleted and supporters refunded.' });
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

describe('Campaigns API (spec-based)', () => {
  let mockCampaignsCollection;
  let mockUsersCollection;
  let mockContributionsCollection;
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

    mockUsersCollection = {
      findOne: vi.fn(),
      updateOne: vi.fn(),
    };

    mockContributionsCollection = {
      find: vi.fn(),
      deleteMany: vi.fn(),
    };

    const app = createCampaignsApp(
      mockCampaignsCollection,
      mockUsersCollection,
      mockContributionsCollection,
    );
    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
  });

  // ---------------------------------------------------------------
  // GET /api/campaigns
  // ---------------------------------------------------------------
  describe('GET /api/campaigns', () => {
    it('should return approved campaigns by default', async () => {
      await harness.start();

      const mockCampaigns = [
        {
          _id: new ObjectId(),
          title: 'Campaign One',
          story: 'Story one',
          category: 'tech',
          fundingGoal: 5000,
          minimumContribution: 50,
          deadline: '2025-12-31',
          creatorEmail: 'creator@example.com',
          creatorName: 'Test Creator',
          amountRaised: 1200,
          status: 'approved',
          createdAt: new Date(),
        },
        {
          _id: new ObjectId(),
          title: 'Campaign Two',
          story: 'Story two',
          category: 'art',
          fundingGoal: 3000,
          minimumContribution: 25,
          deadline: '2025-11-30',
          creatorEmail: 'creator2@example.com',
          creatorName: 'Another Creator',
          amountRaised: 800,
          status: 'approved',
          createdAt: new Date(),
        },
      ];

      mockCampaignsCollection.find.mockReturnValue(mockCursor(mockCampaigns));

      const result = await harness.request('GET', '/api/campaigns');

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toBeDefined();
      expect(result.body.campaigns).toHaveLength(2);
      expect(result.body.campaigns[0].title).toBe('Campaign One');
      expect(result.body.campaigns[1].title).toBe('Campaign Two');
      expect(mockCampaignsCollection.find).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'approved' }),
      );
    });

    it('should return campaigns filtered by category', async () => {
      await harness.start();

      const techCampaigns = [
        {
          _id: new ObjectId(),
          title: 'Tech Campaign',
          story: 'A tech story',
          category: 'tech',
          fundingGoal: 10000,
          minimumContribution: 100,
          deadline: '2025-10-15',
          creatorEmail: 'creator@example.com',
          creatorName: 'Test Creator',
          amountRaised: 5000,
          status: 'approved',
          createdAt: new Date(),
        },
      ];

      mockCampaignsCollection.find.mockReturnValue(mockCursor(techCampaigns));

      const result = await harness.request('GET', '/api/campaigns?category=tech');

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toHaveLength(1);
      expect(result.body.campaigns[0].category).toBe('tech');
      expect(mockCampaignsCollection.find).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'approved', category: 'tech' }),
      );
    });

    it('should return campaigns filtered by custom status', async () => {
      await harness.start();

      const pendingCampaigns = [
        {
          _id: new ObjectId(),
          title: 'Pending Campaign',
          story: 'Not yet approved',
          category: 'tech',
          fundingGoal: 5000,
          minimumContribution: 50,
          deadline: '2025-12-01',
          creatorEmail: 'creator@example.com',
          creatorName: 'Test Creator',
          amountRaised: 0,
          status: 'pending',
          createdAt: new Date(),
        },
      ];

      mockCampaignsCollection.find.mockReturnValue(mockCursor(pendingCampaigns));

      const result = await harness.request('GET', '/api/campaigns?status=pending');

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toHaveLength(1);
      expect(result.body.campaigns[0].status).toBe('pending');
      expect(mockCampaignsCollection.find).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'pending' }),
      );
    });

    it('should return top-funded campaigns sorted by amountRaised descending with limit 6', async () => {
      await harness.start();

      const topCampaigns = Array.from({ length: 3 }, (_, i) => ({
        _id: new ObjectId(),
        title: `Top Campaign ${i + 1}`,
        story: 'Top funded story',
        category: 'tech',
        fundingGoal: 50000,
        minimumContribution: 100,
        deadline: '2025-12-31',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        amountRaised: 50000 - i * 10000,
        status: 'approved',
        createdAt: new Date(),
      }));

      const cursor = mockCursor(topCampaigns);
      mockCampaignsCollection.find.mockReturnValue(cursor);

      const result = await harness.request('GET', '/api/campaigns?top-funded=true');

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toHaveLength(3);
      expect(mockCampaignsCollection.find).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'approved' }),
      );
      expect(cursor.sort).toHaveBeenCalledWith({ amountRaised: -1 });
      expect(cursor.limit).toHaveBeenCalledWith(6);
    });

    it('should return campaigns matching search query (case-insensitive)', async () => {
      await harness.start();

      const matchingCampaigns = [
        {
          _id: new ObjectId(),
          title: 'Tech Innovation Fund',
          story: 'Innovating the future',
          category: 'tech',
          fundingGoal: 20000,
          minimumContribution: 50,
          deadline: '2026-01-15',
          creatorEmail: 'creator@example.com',
          creatorName: 'Test Creator',
          amountRaised: 3000,
          status: 'approved',
          createdAt: new Date(),
        },
      ];

      mockCampaignsCollection.find.mockReturnValue(mockCursor(matchingCampaigns));

      const result = await harness.request('GET', '/api/campaigns?search=innovation');

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toHaveLength(1);
      expect(mockCampaignsCollection.find).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'approved',
          title: { $regex: 'innovation', $options: 'i' },
        }),
      );
    });

    it('should return empty array when no campaigns match', async () => {
      await harness.start();

      mockCampaignsCollection.find.mockReturnValue(mockCursor([]));

      const result = await harness.request('GET', '/api/campaigns?category=unknown');

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toEqual([]);
    });
  });

  // ---------------------------------------------------------------
  // GET /api/campaigns/:id
  // ---------------------------------------------------------------
  describe('GET /api/campaigns/:id', () => {
    it('should return a single campaign by valid id', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const mockCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Single Campaign',
        story: 'Detailed story',
        category: 'education',
        fundingGoal: 15000,
        minimumContribution: 75,
        deadline: '2025-09-30',
        creatorEmail: 'educator@example.com',
        creatorName: 'Teacher',
        amountRaised: 4500,
        status: 'approved',
        createdAt: new Date(),
      };

      mockCampaignsCollection.findOne.mockResolvedValue(mockCampaign);

      const result = await harness.request('GET', `/api/campaigns/${campaignId}`);

      expect(result.status).toBe(200);
      expect(result.body.campaign).toBeDefined();
      expect(result.body.campaign.title).toBe('Single Campaign');
      expect(result.body.campaign.category).toBe('education');
      expect(result.body.campaign.creatorEmail).toBe('educator@example.com');
    });

    it('should return 404 when campaign is not found', async () => {
      await harness.start();

      mockCampaignsCollection.findOne.mockResolvedValue(null);

      const result = await harness.request('GET', '/api/campaigns/507f1f77bcf86cd799439099');

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Campaign not found');
    });
  });

  // ---------------------------------------------------------------
  // POST /api/campaigns
  // ---------------------------------------------------------------
  describe('POST /api/campaigns', () => {
    it('should create a campaign with status "pending" when called by a verified creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id-123',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const mockInsertedId = new ObjectId();
      mockCampaignsCollection.insertOne.mockResolvedValue({ insertedId: mockInsertedId });

      const result = await harness.request(
        'POST',
        '/api/campaigns',
        {
          title: 'Test Campaign',
          story: 'This is a test campaign story.',
          category: 'tech',
          fundingGoal: 10000,
          minimumContribution: 100,
          deadline: '2025-12-31',
          rewardInfo: 'Early bird special',
          imageURL: 'https://example.com/image.jpg',
        },
        { Authorization: 'Bearer creator-valid-jwt' },
      );

      expect(result.status).toBe(201);
      expect(result.body.campaign).toBeDefined();
      expect(result.body.campaign.title).toBe('Test Campaign');
      expect(result.body.campaign.story).toBe('This is a test campaign story.');
      expect(result.body.campaign.category).toBe('tech');
      expect(result.body.campaign.fundingGoal).toBe(10000);
      expect(result.body.campaign.minimumContribution).toBe(100);
      expect(result.body.campaign.deadline).toBe('2025-12-31');
      expect(result.body.campaign.rewardInfo).toBe('Early bird special');
      expect(result.body.campaign.imageURL).toBe('https://example.com/image.jpg');
      expect(result.body.campaign.creatorEmail).toBe('creator@example.com');
      expect(result.body.campaign.creatorName).toBe('Test Creator');
      expect(result.body.campaign.amountRaised).toBe(0);
      expect(result.body.campaign.status).toBe('pending');
      expect(result.body.campaign.createdAt).toBeDefined();
      expect(result.body.campaign._id).toBeDefined();

      expect(mockCampaignsCollection.insertOne).toHaveBeenCalledTimes(1);
      const inserted = mockCampaignsCollection.insertOne.mock.calls[0][0];
      expect(inserted.status).toBe('pending');
      expect(inserted.creatorEmail).toBe('creator@example.com');
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('POST', '/api/campaigns', {
        title: 'Test Campaign',
        story: 'Story',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 100,
        deadline: '2025-12-31',
      });

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 when user is not a creator', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Test Supporter',
        role: 'supporter',
      });

      const result = await harness.request(
        'POST',
        '/api/campaigns',
        {
          title: 'Test Campaign',
          story: 'Story',
          category: 'tech',
          fundingGoal: 10000,
          minimumContribution: 100,
          deadline: '2025-12-31',
        },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can create campaigns');
    });

    it('should return 400 when required fields are missing', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      const result = await harness.request(
        'POST',
        '/api/campaigns',
        {},
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('required');
    });

    it('should return 400 when individual required fields are missing', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      // Missing title
      const result1 = await harness.request(
        'POST',
        '/api/campaigns',
        {
          story: 'A story',
          category: 'tech',
          fundingGoal: 10000,
          minimumContribution: 100,
          deadline: '2025-12-31',
        },
        { Authorization: 'Bearer creator-jwt' },
      );
      expect(result1.status).toBe(400);
      expect(result1.body.message).toContain('required');

      // Missing deadline
      const result2 = await harness.request(
        'POST',
        '/api/campaigns',
        {
          title: 'Test',
          story: 'A story',
          category: 'tech',
          fundingGoal: 10000,
          minimumContribution: 100,
        },
        { Authorization: 'Bearer creator-jwt' },
      );
      expect(result2.status).toBe(400);
      expect(result2.body.message).toContain('required');
    });
  });

  // ---------------------------------------------------------------
  // PUT /api/campaigns/:id
  // ---------------------------------------------------------------
  describe('PUT /api/campaigns/:id', () => {
    it('should update title/story/rewardInfo for the owning creator', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const existingCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Original Title',
        story: 'Original story',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 100,
        deadline: '2025-12-31',
        rewardInfo: 'Old reward',
        imageURL: '',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        amountRaised: 500,
        status: 'approved',
        createdAt: new Date(),
      };

      const updatedCampaign = {
        ...existingCampaign,
        title: 'Updated Title',
        story: 'Updated story',
        rewardInfo: 'New reward info',
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne
        .mockResolvedValueOnce(existingCampaign)  // first call: find before update
        .mockResolvedValueOnce(updatedCampaign);  // second call: find after update
      mockCampaignsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await harness.request(
        'PUT',
        `/api/campaigns/${campaignId}`,
        {
          title: 'Updated Title',
          story: 'Updated story',
          rewardInfo: 'New reward info',
        },
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.campaign).toBeDefined();
      expect(result.body.campaign.title).toBe('Updated Title');
      expect(result.body.campaign.story).toBe('Updated story');
      expect(result.body.campaign.rewardInfo).toBe('New reward info');
      expect(result.body.campaign.category).toBe('tech'); // unchanged

      expect(mockCampaignsCollection.updateOne).toHaveBeenCalledWith(
        { _id: expect.any(ObjectId) },
        { $set: { title: 'Updated Title', story: 'Updated story', rewardInfo: 'New reward info' } },
      );
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
        'PUT',
        '/api/campaigns/507f1f77bcf86cd799439011',
        { title: 'Hacked Title' },
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can update campaigns');
    });

    it('should return 403 when user is not the owner', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const existingCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Original Title',
        story: 'Story',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 100,
        deadline: '2025-12-31',
        creatorEmail: 'owner@example.com', // different from token email
        creatorName: 'Owner Creator',
        amountRaised: 0,
        status: 'approved',
        createdAt: new Date(),
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'other-creator-id',
        email: 'other@example.com',
        name: 'Other Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(existingCampaign);

      const result = await harness.request(
        'PUT',
        `/api/campaigns/${campaignId}`,
        { title: 'Stolen Title' },
        { Authorization: 'Bearer other-creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('You can only update your own campaigns');
    });

    it('should return 404 when campaign is not found', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(null);

      const result = await harness.request(
        'PUT',
        '/api/campaigns/507f1f77bcf86cd799439099',
        { title: 'New Title' },
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Campaign not found');
    });

    it('should return 400 when no updatable fields are provided', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const existingCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Title',
        story: 'Story',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 100,
        deadline: '2025-12-31',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        amountRaised: 0,
        status: 'approved',
        createdAt: new Date(),
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(existingCampaign);

      const result = await harness.request(
        'PUT',
        `/api/campaigns/${campaignId}`,
        { category: 'art', fundingGoal: 5000 }, // not updatable fields
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('At least one field');
    });
  });

  // ---------------------------------------------------------------
  // DELETE /api/campaigns/:id
  // ---------------------------------------------------------------
  describe('DELETE /api/campaigns/:id', () => {
    it('should delete campaign and refund approved supporters credits', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const existingCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Campaign to Delete',
        story: 'Story',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 100,
        deadline: '2025-12-31',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        amountRaised: 3000,
        status: 'approved',
        createdAt: new Date(),
      };

      const approvedContributions = [
        { _id: 'c1', campaignId, amount: 1000, supporterEmail: 's1@example.com', status: 'approved' },
        { _id: 'c2', campaignId, amount: 500, supporterEmail: 's2@example.com', status: 'approved' },
      ];

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(existingCampaign);
      mockContributionsCollection.find.mockReturnValue(mockCursor(approvedContributions));
      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockContributionsCollection.deleteMany.mockResolvedValue({ deletedCount: 2 });
      mockCampaignsCollection.deleteOne.mockResolvedValue({ deletedCount: 1 });

      const result = await harness.request(
        'DELETE',
        `/api/campaigns/${campaignId}`,
        undefined,
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('deleted');

      // Verify refund: each approved supporter's credits incremented
      expect(mockUsersCollection.updateOne).toHaveBeenCalledTimes(2);
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 's1@example.com' },
        { $inc: { credits: 1000 } },
      );
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email: 's2@example.com' },
        { $inc: { credits: 500 } },
      );

      // Verify all contributions deleted
      expect(mockContributionsCollection.deleteMany).toHaveBeenCalledWith(
        { campaignId },
      );

      // Verify campaign deleted
      expect(mockCampaignsCollection.deleteOne).toHaveBeenCalledWith(
        { _id: expect.any(ObjectId) },
      );
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
        'DELETE',
        '/api/campaigns/507f1f77bcf86cd799439011',
        undefined,
        { Authorization: 'Bearer supporter-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Only creators can delete campaigns');
    });

    it('should return 403 when user is not the owner', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const existingCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Someone Elses Campaign',
        story: 'Story',
        category: 'art',
        fundingGoal: 5000,
        minimumContribution: 50,
        deadline: '2025-11-30',
        creatorEmail: 'owner@example.com',
        creatorName: 'Owner',
        amountRaised: 100,
        status: 'approved',
        createdAt: new Date(),
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'other-creator-id',
        email: 'other@example.com',
        name: 'Other Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(existingCampaign);

      const result = await harness.request(
        'DELETE',
        `/api/campaigns/${campaignId}`,
        undefined,
        { Authorization: 'Bearer other-creator-jwt' },
      );

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('You can only delete your own campaigns');
    });

    it('should return 404 when campaign is not found', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(null);

      const result = await harness.request(
        'DELETE',
        '/api/campaigns/507f1f77bcf86cd799439099',
        undefined,
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Campaign not found');
    });

    it('should delete campaign when there are no approved contributions', async () => {
      await harness.start();

      const campaignId = new ObjectId().toString();
      const existingCampaign = {
        _id: new ObjectId(campaignId),
        title: 'Campaign with no contributions',
        story: 'Story',
        category: 'tech',
        fundingGoal: 10000,
        minimumContribution: 100,
        deadline: '2025-12-31',
        creatorEmail: 'creator@example.com',
        creatorName: 'Test Creator',
        amountRaised: 0,
        status: 'pending',
        createdAt: new Date(),
      };

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'Test Creator',
        role: 'creator',
      });

      mockCampaignsCollection.findOne.mockResolvedValue(existingCampaign);
      mockContributionsCollection.find.mockReturnValue(mockCursor([]));
      mockContributionsCollection.deleteMany.mockResolvedValue({ deletedCount: 0 });
      mockCampaignsCollection.deleteOne.mockResolvedValue({ deletedCount: 1 });

      const result = await harness.request(
        'DELETE',
        `/api/campaigns/${campaignId}`,
        undefined,
        { Authorization: 'Bearer creator-jwt' },
      );

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('deleted');

      // No refunds issued
      expect(mockUsersCollection.updateOne).not.toHaveBeenCalled();

      // Contributions deleteMany still called
      expect(mockContributionsCollection.deleteMany).toHaveBeenCalled();
      expect(mockCampaignsCollection.deleteOne).toHaveBeenCalled();
    });
  });
});
