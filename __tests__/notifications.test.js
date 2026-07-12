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
 * Helper: creates a test Express app with notification routes and the routes
 * that produce notification side-effects (contributions, campaigns, withdrawals).
 * Routes implement the spec-defined behaviour.
 */
function createNotificationsApp(mockCollections) {
  const {
    users: mockUsers,
    campaigns: mockCampaigns,
    contributions: mockContributions,
    withdrawals: mockWithdrawals,
    notifications: mockNotifications,
  } = mockCollections;

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

  // ─────────────────────────────────────────────
  // GET /api/notifications
  // ─────────────────────────────────────────────
  app.get('/api/notifications', verifyToken, async (req, res) => {
    try {
      const notifications = await mockNotifications
        .find({ toEmail: req.user.email })
        .sort({ createdAt: -1 })
        .limit(50)
        .toArray();
      return res.json({ notifications });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // PATCH /api/notifications/:id/read
  // ─────────────────────────────────────────────
  app.patch('/api/notifications/:id/read', verifyToken, async (req, res) => {
    try {
      const notification = await mockNotifications.findOne({ _id: req.params.id });
      if (!notification) {
        return res.status(404).json({ message: 'Notification not found.' });
      }
      if (notification.toEmail !== req.user.email) {
        return res.status(403).json({ message: 'You can only mark your own notifications as read.' });
      }
      await mockNotifications.updateOne(
        { _id: req.params.id },
        { $set: { read: true } },
      );
      const updated = await mockNotifications.findOne({ _id: req.params.id });
      return res.json({ notification: updated });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // POST /api/contributions  (supporter submits a contribution)
  // Notification side-effect: notify campaign creator
  // ─────────────────────────────────────────────
  app.post('/api/contributions', verifyToken, requireRole('supporter'), async (req, res) => {
    try {
      const { campaignId, amount } = req.body;
      if (!campaignId || !amount) {
        return res.status(400).json({ message: 'Campaign ID and amount are required.' });
      }

      const campaign = await mockCampaigns.findOne({ _id: campaignId });
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

      const user = await mockUsers.findOne({ email: req.user.email });
      if (!user || user.credits < contributionAmount) {
        return res.status(400).json({ message: 'Insufficient credits.' });
      }

      await mockUsers.updateOne(
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

      const result = await mockContributions.insertOne(contribution);
      const saved = { ...contribution, _id: result.insertedId };

      // Notification side-effect: notify campaign creator
      if (campaign.creatorEmail) {
        await mockNotifications.insertOne({
          message: `${req.user.name} contributed ${contributionAmount} credits to ${campaign.title}`,
          toEmail: campaign.creatorEmail,
          fromEmail: req.user.email,
          actionRoute: '/dashboard/creator',
          read: false,
          createdAt: new Date(),
        });
      }

      return res.status(201).json({ contribution: saved });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // PATCH /api/contributions/:id/approve  (creator approves a contribution)
  // Notification side-effect: notify supporter
  // ─────────────────────────────────────────────
  app.patch('/api/contributions/:id/approve', verifyToken, requireRole('creator'), async (req, res) => {
    try {
      const contribution = await mockContributions.findOne({ _id: req.params.id });
      if (!contribution) {
        return res.status(404).json({ message: 'Contribution not found.' });
      }

      if (contribution.creatorEmail !== req.user.email) {
        return res.status(403).json({ message: 'This contribution does not belong to your campaign.' });
      }

      if (contribution.status !== 'pending') {
        return res.status(400).json({ message: 'Contribution is not in pending status.' });
      }

      await mockContributions.updateOne(
        { _id: req.params.id },
        { $set: { status: 'approved' } },
      );

      await mockCampaigns.updateOne(
        { _id: contribution.campaignId },
        { $inc: { amountRaised: contribution.amount } },
      );

      // Notification side-effect: notify supporter
      if (contribution.supporterEmail) {
        await mockNotifications.insertOne({
          message: `Your contribution of ${contribution.amount} credits to ${contribution.campaignTitle} was approved`,
          toEmail: contribution.supporterEmail,
          fromEmail: req.user.email,
          actionRoute: '/dashboard/supporter/my-contributions',
          read: false,
          createdAt: new Date(),
        });
      }

      return res.json({ message: 'Contribution approved.', contribution: { ...contribution, status: 'approved' } });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // PATCH /api/contributions/:id/reject  (creator rejects a contribution)
  // Notification side-effect: notify supporter
  // ─────────────────────────────────────────────
  app.patch('/api/contributions/:id/reject', verifyToken, requireRole('creator'), async (req, res) => {
    try {
      const contribution = await mockContributions.findOne({ _id: req.params.id });
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
      await mockUsers.updateOne(
        { email: contribution.supporterEmail },
        { $inc: { credits: contribution.amount } },
      );

      await mockContributions.updateOne(
        { _id: req.params.id },
        { $set: { status: 'rejected' } },
      );

      // Notification side-effect: notify supporter
      if (contribution.supporterEmail) {
        await mockNotifications.insertOne({
          message: `Your contribution of ${contribution.amount} credits to ${contribution.campaignTitle} was rejected`,
          toEmail: contribution.supporterEmail,
          fromEmail: req.user.email,
          actionRoute: '/dashboard/supporter/my-contributions',
          read: false,
          createdAt: new Date(),
        });
      }

      return res.json({ message: 'Contribution rejected and supporter refunded.', contribution: { ...contribution, status: 'rejected' } });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // PATCH /api/campaigns/:id/approve  (admin approves a campaign)
  // Notification side-effect: notify campaign creator
  // ─────────────────────────────────────────────
  app.patch('/api/campaigns/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const campaign = await mockCampaigns.findOne({ _id: req.params.id });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.status !== 'pending') {
        return res.status(400).json({ message: 'Only pending campaigns can be approved.' });
      }

      await mockCampaigns.updateOne(
        { _id: req.params.id },
        { $set: { status: 'approved' } },
      );
      const updated = await mockCampaigns.findOne({ _id: req.params.id });

      // Notification side-effect: notify campaign creator
      if (campaign.creatorEmail) {
        await mockNotifications.insertOne({
          message: `Your campaign ${campaign.title} has been approved`,
          toEmail: campaign.creatorEmail,
          fromEmail: req.user.email,
          actionRoute: '/dashboard/creator/my-campaigns',
          read: false,
          createdAt: new Date(),
        });
      }

      return res.json({ campaign: updated });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // PATCH /api/campaigns/:id/reject  (admin rejects a campaign)
  // Notification side-effect: notify campaign creator
  // ─────────────────────────────────────────────
  app.patch('/api/campaigns/:id/reject', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const campaign = await mockCampaigns.findOne({ _id: req.params.id });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.status !== 'pending') {
        return res.status(400).json({ message: 'Only pending campaigns can be rejected.' });
      }

      await mockCampaigns.updateOne(
        { _id: req.params.id },
        { $set: { status: 'rejected' } },
      );
      const updated = await mockCampaigns.findOne({ _id: req.params.id });

      // Notification side-effect: notify campaign creator
      if (campaign.creatorEmail) {
        await mockNotifications.insertOne({
          message: `Your campaign ${campaign.title} has been rejected`,
          toEmail: campaign.creatorEmail,
          fromEmail: req.user.email,
          actionRoute: '/dashboard/creator/my-campaigns',
          read: false,
          createdAt: new Date(),
        });
      }

      return res.json({ campaign: updated });
    } catch (error) {
      return res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─────────────────────────────────────────────
  // PATCH /api/withdrawals/:id/approve  (admin approves a withdrawal)
  // Notification side-effect: notify withdrawal creator
  // ─────────────────────────────────────────────
  app.patch('/api/withdrawals/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const withdrawal = await mockWithdrawals.findOne({ _id: req.params.id });
      if (!withdrawal) {
        return res.status(404).json({ message: 'Withdrawal not found.' });
      }
      if (withdrawal.status !== 'pending') {
        return res.status(400).json({ message: 'Only pending withdrawals can be approved.' });
      }

      await mockWithdrawals.updateOne(
        { _id: req.params.id },
        { $set: { status: 'approved' } },
      );
      const updated = await mockWithdrawals.findOne({ _id: req.params.id });

      // Notification side-effect: notify withdrawal creator
      if (withdrawal.creatorEmail) {
        await mockNotifications.insertOne({
          message: `Your withdrawal of ${withdrawal.withdrawalCredit} credits has been approved`,
          toEmail: withdrawal.creatorEmail,
          fromEmail: req.user.email,
          actionRoute: '/dashboard/creator/withdrawals',
          read: false,
          createdAt: new Date(),
        });
      }

      return res.json({ withdrawal: updated });
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

describe('Notifications API (spec-based)', () => {
  let mockUsers;
  let mockCampaigns;
  let mockContributions;
  let mockWithdrawals;
  let mockNotifications;
  let harness;

  /**
   * Helper: sets up jwt.verify mock for a given user role and returns
   * the Authorization header value.
   */
  function authToken(overrides = {}) {
    vi.spyOn(jwt, 'verify').mockReturnValue({
      id: 'user-id-1',
      email: 'user@example.com',
      name: 'Test User',
      role: 'supporter',
      ...overrides,
    });
    return 'Bearer valid-jwt-token';
  }

  beforeEach(() => {
    vi.clearAllMocks();

    mockUsers = {
      findOne: vi.fn(),
      updateOne: vi.fn(),
    };

    mockCampaigns = {
      findOne: vi.fn(),
      find: vi.fn(() => mockCursor([])),
      updateOne: vi.fn(),
    };

    mockContributions = {
      findOne: vi.fn(),
      find: vi.fn(() => mockCursor([])),
      insertOne: vi.fn(),
      updateOne: vi.fn(),
    };

    mockWithdrawals = {
      findOne: vi.fn(),
      find: vi.fn(() => mockCursor([])),
      updateOne: vi.fn(),
    };

    mockNotifications = {
      find: vi.fn(() => mockCursor([])),
      findOne: vi.fn(),
      insertOne: vi.fn(),
      updateOne: vi.fn(),
    };

    const app = createNotificationsApp({
      users: mockUsers,
      campaigns: mockCampaigns,
      contributions: mockContributions,
      withdrawals: mockWithdrawals,
      notifications: mockNotifications,
    });

    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
    vi.restoreAllMocks();
  });

  // ═══════════════════════════════════════════════════════════════
  // GET /api/notifications
  // ═══════════════════════════════════════════════════════════════
  describe('GET /api/notifications', () => {
    it('should return the authenticated user notifications sorted by createdAt desc, limited to 50', async () => {
      await harness.start();

      const mockNotifs = [
        { _id: 'n1', message: 'Second', toEmail: 'user@example.com', createdAt: new Date('2025-06-02') },
        { _id: 'n2', message: 'First', toEmail: 'user@example.com', createdAt: new Date('2025-06-01') },
      ];

      const cursor = mockCursor(mockNotifs);
      mockNotifications.find.mockReturnValue(cursor);

      authToken({ email: 'user@example.com' });

      const result = await harness.request('GET', '/api/notifications', undefined, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.notifications).toBeDefined();
      expect(result.body.notifications).toHaveLength(2);
      expect(result.body.notifications[0].message).toBe('Second');
      expect(result.body.notifications[1].message).toBe('First');

      expect(mockNotifications.find).toHaveBeenCalledWith({ toEmail: 'user@example.com' });
      expect(cursor.sort).toHaveBeenCalledWith({ createdAt: -1 });
      expect(cursor.limit).toHaveBeenCalledWith(50);
    });

    it('should return empty array when the user has no notifications', async () => {
      await harness.start();

      mockNotifications.find.mockReturnValue(mockCursor([]));

      authToken({ email: 'empty@example.com' });

      const result = await harness.request('GET', '/api/notifications', undefined, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.notifications).toEqual([]);
    });

    it('should return only notifications for the authenticated user (not other users)', async () => {
      await harness.start();

      // Only return notifications where toEmail matches req.user.email
      const userNotifs = [
        { _id: 'n1', message: 'Your notification', toEmail: 'user@example.com', createdAt: new Date() },
      ];

      const cursor = mockCursor(userNotifs);
      mockNotifications.find.mockReturnValue(cursor);

      authToken({ email: 'user@example.com' });

      const result = await harness.request('GET', '/api/notifications', undefined, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.notifications).toHaveLength(1);
      expect(mockNotifications.find).toHaveBeenCalledWith({ toEmail: 'user@example.com' });
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('GET', '/api/notifications');

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 401 when token is invalid', async () => {
      await harness.start();

      vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new Error('jwt expired');
      });

      const result = await harness.request('GET', '/api/notifications', undefined, {
        Authorization: 'Bearer bad-token',
      });

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Invalid token');
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // PATCH /api/notifications/:id/read
  // ═══════════════════════════════════════════════════════════════
  describe('PATCH /api/notifications/:id/read', () => {
    it('should mark a notification as read and return the updated notification', async () => {
      await harness.start();

      const existingNotif = {
        _id: 'notif-1',
        message: 'Test notification',
        toEmail: 'user@example.com',
        fromEmail: 'other@example.com',
        actionRoute: '/dashboard/creator',
        read: false,
        createdAt: new Date(),
      };

      const updatedNotif = { ...existingNotif, read: true };

      mockNotifications.findOne
        .mockResolvedValueOnce(existingNotif)   // first findOne (check exists + ownership)
        .mockResolvedValueOnce(updatedNotif);    // second findOne (return updated)

      authToken({ email: 'user@example.com' });

      const result = await harness.request('PATCH', '/api/notifications/notif-1/read', {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.notification).toBeDefined();
      expect(result.body.notification.read).toBe(true);
      expect(result.body.notification.message).toBe('Test notification');

      expect(mockNotifications.findOne).toHaveBeenCalledWith({ _id: 'notif-1' });
      expect(mockNotifications.updateOne).toHaveBeenCalledWith(
        { _id: 'notif-1' },
        { $set: { read: true } },
      );
    });

    it('should return 404 when notification does not exist', async () => {
      await harness.start();

      mockNotifications.findOne.mockResolvedValue(null);

      authToken({ email: 'user@example.com' });

      const result = await harness.request('PATCH', '/api/notifications/nonexistent/read', {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Notification not found');
      expect(mockNotifications.updateOne).not.toHaveBeenCalled();
    });

    it('should return 403 when notification toEmail does not match the authenticated user', async () => {
      await harness.start();

      const otherUsersNotif = {
        _id: 'notif-2',
        message: 'Someone elses notification',
        toEmail: 'other@example.com',
        fromEmail: 'someone@example.com',
        read: false,
        createdAt: new Date(),
      };

      mockNotifications.findOne.mockResolvedValue(otherUsersNotif);

      authToken({ email: 'user@example.com' });

      const result = await harness.request('PATCH', '/api/notifications/notif-2/read', {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(403);
      expect(result.body.message).toContain('You can only mark your own notifications as read');
      expect(mockNotifications.updateOne).not.toHaveBeenCalled();
    });

    it('should return 401 when no auth token is provided', async () => {
      await harness.start();

      const result = await harness.request('PATCH', '/api/notifications/notif-1/read', {});

      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Notification side-effect: POST /api/contributions
  // ═══════════════════════════════════════════════════════════════
  describe('Notification side-effect: POST /api/contributions', () => {
    it('should insert a notification for the campaign creator when a contribution is made', async () => {
      await harness.start();

      authToken({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Jane Supporter',
        role: 'supporter',
      });

      const campaignId = 'camp-1';
      const mockCampaign = {
        _id: campaignId,
        title: 'My Great Campaign',
        minimumContribution: 50,
        creatorEmail: 'creator@example.com',
        creatorName: 'John Creator',
        status: 'approved',
      };

      const mockUser = {
        _id: 'user-id',
        email: 'supporter@example.com',
        credits: 500,
      };

      mockCampaigns.findOne.mockResolvedValue(mockCampaign);
      mockUsers.findOne.mockResolvedValue(mockUser);
      mockUsers.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockContributions.insertOne.mockResolvedValue({ insertedId: 'contrib-1' });
      mockNotifications.insertOne.mockResolvedValue({ insertedId: 'notif-1' });

      const result = await harness.request('POST', '/api/contributions', {
        campaignId,
        amount: 200,
      }, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(201);
      expect(result.body.contribution).toBeDefined();
      expect(result.body.contribution.status).toBe('pending');

      // Verify notification was inserted for the campaign creator
      expect(mockNotifications.insertOne).toHaveBeenCalledTimes(1);
      const insertedNotif = mockNotifications.insertOne.mock.calls[0][0];
      expect(insertedNotif.message).toBe('Jane Supporter contributed 200 credits to My Great Campaign');
      expect(insertedNotif.toEmail).toBe('creator@example.com');
      expect(insertedNotif.fromEmail).toBe('supporter@example.com');
      expect(insertedNotif.actionRoute).toBe('/dashboard/creator');
      expect(insertedNotif.read).toBe(false);
      expect(insertedNotif.createdAt).toBeDefined();
    });

    it('should still succeed when campaign has no creatorEmail (graceful skip)', async () => {
      await harness.start();

      authToken({
        id: 'supporter-id',
        email: 'supporter@example.com',
        name: 'Jane Supporter',
        role: 'supporter',
      });

      const mockCampaign = {
        _id: 'camp-2',
        title: 'Orphan Campaign',
        minimumContribution: 10,
        creatorEmail: null,
        status: 'approved',
      };

      const mockUser = {
        _id: 'user-id',
        email: 'supporter@example.com',
        credits: 500,
      };

      mockCampaigns.findOne.mockResolvedValue(mockCampaign);
      mockUsers.findOne.mockResolvedValue(mockUser);
      mockUsers.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockContributions.insertOne.mockResolvedValue({ insertedId: 'contrib-2' });

      const result = await harness.request('POST', '/api/contributions', {
        campaignId: 'camp-2',
        amount: 50,
      }, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(201);
      // No notification should be inserted
      expect(mockNotifications.insertOne).not.toHaveBeenCalled();
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Notification side-effect: PATCH /api/contributions/:id/approve
  // ═══════════════════════════════════════════════════════════════
  describe('Notification side-effect: PATCH /api/contributions/:id/approve', () => {
    it('should insert a notification for the supporter when a contribution is approved', async () => {
      await harness.start();

      authToken({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'John Creator',
        role: 'creator',
      });

      const contributionId = 'contrib-1';
      const mockContribution = {
        _id: contributionId,
        campaignId: 'camp-1',
        campaignTitle: 'My Campaign',
        amount: 500,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Jane Supporter',
        creatorEmail: 'creator@example.com',
        status: 'pending',
      };

      mockContributions.findOne.mockResolvedValue(mockContribution);
      mockContributions.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockCampaigns.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockNotifications.insertOne.mockResolvedValue({ insertedId: 'notif-1' });

      const result = await harness.request('PATCH', `/api/contributions/${contributionId}/approve`, {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('approved');

      // Verify notification was inserted for the supporter
      expect(mockNotifications.insertOne).toHaveBeenCalledTimes(1);
      const insertedNotif = mockNotifications.insertOne.mock.calls[0][0];
      expect(insertedNotif.message).toBe('Your contribution of 500 credits to My Campaign was approved');
      expect(insertedNotif.toEmail).toBe('supporter@example.com');
      expect(insertedNotif.fromEmail).toBe('creator@example.com');
      expect(insertedNotif.actionRoute).toBe('/dashboard/supporter/my-contributions');
      expect(insertedNotif.read).toBe(false);
      expect(insertedNotif.createdAt).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Notification side-effect: PATCH /api/contributions/:id/reject
  // ═══════════════════════════════════════════════════════════════
  describe('Notification side-effect: PATCH /api/contributions/:id/reject', () => {
    it('should insert a notification for the supporter when a contribution is rejected', async () => {
      await harness.start();

      authToken({
        id: 'creator-id',
        email: 'creator@example.com',
        name: 'John Creator',
        role: 'creator',
      });

      const contributionId = 'contrib-2';
      const mockContribution = {
        _id: contributionId,
        campaignId: 'camp-2',
        campaignTitle: 'Test Campaign',
        amount: 250,
        supporterEmail: 'supporter@example.com',
        supporterName: 'Jane Supporter',
        creatorEmail: 'creator@example.com',
        status: 'pending',
      };

      mockContributions.findOne.mockResolvedValue(mockContribution);
      mockUsers.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockContributions.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockNotifications.insertOne.mockResolvedValue({ insertedId: 'notif-2' });

      const result = await harness.request('PATCH', `/api/contributions/${contributionId}/reject`, {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('rejected');

      // Verify notification was inserted for the supporter
      expect(mockNotifications.insertOne).toHaveBeenCalledTimes(1);
      const insertedNotif = mockNotifications.insertOne.mock.calls[0][0];
      expect(insertedNotif.message).toBe('Your contribution of 250 credits to Test Campaign was rejected');
      expect(insertedNotif.toEmail).toBe('supporter@example.com');
      expect(insertedNotif.fromEmail).toBe('creator@example.com');
      expect(insertedNotif.actionRoute).toBe('/dashboard/supporter/my-contributions');
      expect(insertedNotif.read).toBe(false);
      expect(insertedNotif.createdAt).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Notification side-effect: PATCH /api/campaigns/:id/approve
  // ═══════════════════════════════════════════════════════════════
  describe('Notification side-effect: PATCH /api/campaigns/:id/approve', () => {
    it('should insert a notification for the campaign creator when a campaign is approved', async () => {
      await harness.start();

      authToken({
        id: 'admin-id',
        email: 'admin@fundfrog.com',
        name: 'Admin User',
        role: 'admin',
      });

      const campaignId = 'camp-1';
      const pendingCampaign = {
        _id: campaignId,
        title: 'My Campaign',
        creatorEmail: 'creator@example.com',
        creatorName: 'John Creator',
        status: 'pending',
      };
      const approvedCampaign = { ...pendingCampaign, status: 'approved' };

      mockCampaigns.findOne
        .mockResolvedValueOnce(pendingCampaign)
        .mockResolvedValueOnce(approvedCampaign);
      mockCampaigns.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockNotifications.insertOne.mockResolvedValue({ insertedId: 'notif-1' });

      const result = await harness.request('PATCH', `/api/campaigns/${campaignId}/approve`, {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.campaign.status).toBe('approved');

      // Verify notification was inserted for the campaign creator
      expect(mockNotifications.insertOne).toHaveBeenCalledTimes(1);
      const insertedNotif = mockNotifications.insertOne.mock.calls[0][0];
      expect(insertedNotif.message).toBe('Your campaign My Campaign has been approved');
      expect(insertedNotif.toEmail).toBe('creator@example.com');
      expect(insertedNotif.fromEmail).toBe('admin@fundfrog.com');
      expect(insertedNotif.actionRoute).toBe('/dashboard/creator/my-campaigns');
      expect(insertedNotif.read).toBe(false);
      expect(insertedNotif.createdAt).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Notification side-effect: PATCH /api/campaigns/:id/reject
  // ═══════════════════════════════════════════════════════════════
  describe('Notification side-effect: PATCH /api/campaigns/:id/reject', () => {
    it('should insert a notification for the campaign creator when a campaign is rejected', async () => {
      await harness.start();

      authToken({
        id: 'admin-id',
        email: 'admin@fundfrog.com',
        name: 'Admin User',
        role: 'admin',
      });

      const campaignId = 'camp-2';
      const pendingCampaign = {
        _id: campaignId,
        title: 'My Rejected Campaign',
        creatorEmail: 'creator@example.com',
        creatorName: 'John Creator',
        status: 'pending',
      };
      const rejectedCampaign = { ...pendingCampaign, status: 'rejected' };

      mockCampaigns.findOne
        .mockResolvedValueOnce(pendingCampaign)
        .mockResolvedValueOnce(rejectedCampaign);
      mockCampaigns.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockNotifications.insertOne.mockResolvedValue({ insertedId: 'notif-2' });

      const result = await harness.request('PATCH', `/api/campaigns/${campaignId}/reject`, {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.campaign.status).toBe('rejected');

      // Verify notification was inserted for the campaign creator
      expect(mockNotifications.insertOne).toHaveBeenCalledTimes(1);
      const insertedNotif = mockNotifications.insertOne.mock.calls[0][0];
      expect(insertedNotif.message).toBe('Your campaign My Rejected Campaign has been rejected');
      expect(insertedNotif.toEmail).toBe('creator@example.com');
      expect(insertedNotif.fromEmail).toBe('admin@fundfrog.com');
      expect(insertedNotif.actionRoute).toBe('/dashboard/creator/my-campaigns');
      expect(insertedNotif.read).toBe(false);
      expect(insertedNotif.createdAt).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // Notification side-effect: PATCH /api/withdrawals/:id/approve
  // ═══════════════════════════════════════════════════════════════
  describe('Notification side-effect: PATCH /api/withdrawals/:id/approve', () => {
    it('should insert a notification for the withdrawal creator when a withdrawal is approved', async () => {
      await harness.start();

      authToken({
        id: 'admin-id',
        email: 'admin@fundfrog.com',
        name: 'Admin User',
        role: 'admin',
      });

      const withdrawalId = 'w-1';
      const pendingWithdrawal = {
        _id: withdrawalId,
        creatorEmail: 'creator@example.com',
        withdrawalCredit: 500,
        status: 'pending',
      };
      const approvedWithdrawal = { ...pendingWithdrawal, status: 'approved' };

      mockWithdrawals.findOne
        .mockResolvedValueOnce(pendingWithdrawal)
        .mockResolvedValueOnce(approvedWithdrawal);
      mockWithdrawals.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockNotifications.insertOne.mockResolvedValue({ insertedId: 'notif-1' });

      const result = await harness.request('PATCH', `/api/withdrawals/${withdrawalId}/approve`, {}, {
        Authorization: 'Bearer valid-jwt-token',
      });

      expect(result.status).toBe(200);
      expect(result.body.withdrawal.status).toBe('approved');

      // Verify notification was inserted for the withdrawal creator
      expect(mockNotifications.insertOne).toHaveBeenCalledTimes(1);
      const insertedNotif = mockNotifications.insertOne.mock.calls[0][0];
      expect(insertedNotif.message).toBe('Your withdrawal of 500 credits has been approved');
      expect(insertedNotif.toEmail).toBe('creator@example.com');
      expect(insertedNotif.fromEmail).toBe('admin@fundfrog.com');
      expect(insertedNotif.actionRoute).toBe('/dashboard/creator/withdrawals');
      expect(insertedNotif.read).toBe(false);
      expect(insertedNotif.createdAt).toBeDefined();
    });
  });
});
