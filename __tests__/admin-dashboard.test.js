import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import http from 'http';
import jwt from 'jsonwebtoken';

/**
 * Helper: creates a test Express app with all admin dashboard routes.
 */
function createAdminApp(mockCollections) {
  const { users, campaigns, contributions, reports, withdrawals } = mockCollections;
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

  // ─── GET /api/admin/stats ──────────────────────────────────────
  app.get('/api/admin/stats', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const supporters = await users.countDocuments({ role: 'supporter' });
      const creators = await users.countDocuments({ role: 'creator' });
      const creditResult = await users.aggregate([
        { $group: { _id: null, total: { $sum: '$credits' } } },
      ]).toArray();
      const totalCredits = creditResult.length > 0 ? creditResult[0].total : 0;
      res.json({ stats: { totalSupporters: supporters, totalCreators: creators, totalCredits, totalPayments: 0 } });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── GET /api/admin/pending-campaigns ─────────────────────────
  app.get('/api/admin/pending-campaigns', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const pending = await campaigns.find({ status: 'pending' }).sort({ createdAt: -1 }).toArray();
      res.json({ campaigns: pending });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── PATCH /api/campaigns/:id/approve ──────────────────────────
  app.patch('/api/campaigns/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const campaign = await campaigns.findOne({ _id: req.params.id });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.status !== 'pending') {
        return res.status(400).json({ message: 'Only pending campaigns can be approved.' });
      }
      await campaigns.updateOne({ _id: req.params.id }, { $set: { status: 'approved' } });
      const updated = await campaigns.findOne({ _id: req.params.id });
      res.json({ campaign: updated });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── PATCH /api/campaigns/:id/reject ───────────────────────────
  app.patch('/api/campaigns/:id/reject', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const campaign = await campaigns.findOne({ _id: req.params.id });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      if (campaign.status !== 'pending') {
        return res.status(400).json({ message: 'Only pending campaigns can be rejected.' });
      }
      await campaigns.updateOne({ _id: req.params.id }, { $set: { status: 'rejected' } });
      const updated = await campaigns.findOne({ _id: req.params.id });
      res.json({ campaign: updated });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── GET /api/admin/pending-withdrawals ───────────────────────
  app.get('/api/admin/pending-withdrawals', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const pending = await withdrawals.find({ status: 'pending' }).sort({ date: -1 }).toArray();
      res.json({ withdrawals: pending });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── PATCH /api/withdrawals/:id/approve ───────────────────────
  app.patch('/api/withdrawals/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const withdrawal = await withdrawals.findOne({ _id: req.params.id });
      if (!withdrawal) {
        return res.status(404).json({ message: 'Withdrawal not found.' });
      }
      if (withdrawal.status !== 'pending') {
        return res.status(400).json({ message: 'Only pending withdrawals can be approved.' });
      }
      await withdrawals.updateOne({ _id: req.params.id }, { $set: { status: 'approved' } });
      const updated = await withdrawals.findOne({ _id: req.params.id });
      res.json({ withdrawal: updated });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── GET /api/users ─────────────────────────────────────────────
  app.get('/api/users', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const allUsers = await users.find({}).project({ password: 0 }).toArray();
      const sanitized = allUsers.map((u) => ({
        id: u._id.toString(),
        name: u.name,
        email: u.email,
        photoURL: u.photoURL || '',
        role: u.role,
        credits: u.credits,
        createdAt: u.createdAt,
      }));
      res.json({ users: sanitized });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── PATCH /api/users/:id ──────────────────────────────────────
  app.patch('/api/users/:id', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const { role } = req.body;
      if (!role || !['supporter', 'creator', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Role must be "supporter", "creator", or "admin".' });
      }
      const user = await users.findOne({ _id: req.params.id });
      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      }
      await users.updateOne({ _id: req.params.id }, { $set: { role } });
      const updated = await users.findOne({ _id: req.params.id });
      res.json({ user: sanitizeUser(updated) });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── DELETE /api/users/:id ─────────────────────────────────────
  app.delete('/api/users/:id', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const user = await users.findOne({ _id: req.params.id });
      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      }
      const adminCount = await users.countDocuments({ role: 'admin' });
      if (adminCount <= 1 && user.role === 'admin') {
        return res.status(400).json({ message: 'Cannot delete the last admin.' });
      }
      await users.deleteOne({ _id: req.params.id });
      res.json({ message: 'User deleted successfully.' });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── DELETE /api/campaigns/:id/admin ───────────────────────────
  app.delete('/api/campaigns/:id/admin', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const campaign = await campaigns.findOne({ _id: req.params.id });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      // Refund all approved supporters
      const approvedContributions = await contributions.find({ campaignId: req.params.id, status: 'approved' }).toArray();
      for (const c of approvedContributions) {
        await users.updateOne({ email: c.supporterEmail }, { $inc: { credits: c.amount } });
      }
      await contributions.deleteMany({ campaignId: req.params.id });
      await campaigns.deleteOne({ _id: req.params.id });
      res.json({ message: 'Campaign deleted and supporters refunded.' });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── GET /api/reports ──────────────────────────────────────────
  app.get('/api/reports', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const allReports = await reports.find({}).sort({ date: -1 }).toArray();
      res.json({ reports: allReports });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── POST /api/reports ─────────────────────────────────────────
  app.post('/api/reports', verifyToken, async (req, res) => {
    try {
      const { campaignId, campaignTitle, reason } = req.body;
      if (!campaignId || !campaignTitle || !reason) {
        return res.status(400).json({ message: 'Campaign ID, campaign title, and reason are required.' });
      }
      const report = {
        reporterEmail: req.user.email,
        campaignTitle,
        campaignId,
        reason,
        date: new Date(),
      };
      const result = await reports.insertOne(report);
      const saved = { ...report, _id: result.insertedId };
      res.status(201).json({ report: saved });
    } catch (error) {
      res.status(500).json({ message: 'Server error.' });
    }
  });

  // ─── DELETE /api/campaigns/:id/suspend ─────────────────────────
  app.delete('/api/campaigns/:id/suspend', verifyToken, requireRole('admin'), async (req, res) => {
    try {
      const campaign = await campaigns.findOne({ _id: req.params.id });
      if (!campaign) {
        return res.status(404).json({ message: 'Campaign not found.' });
      }
      await campaigns.updateOne({ _id: req.params.id }, { $set: { status: 'suspended' } });
      const updated = await campaigns.findOne({ _id: req.params.id });
      res.json({ campaign: updated });
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
 * Helper: starts the app on a random port and makes requests using node:http.
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

/**
 * Helper: creates a mock MongoDB cursor that returns the given data.
 */
function mockCursor(data) {
  return {
    sort: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    skip: vi.fn().mockReturnThis(),
    project: vi.fn().mockReturnThis(),
    toArray: vi.fn().mockResolvedValue(data),
  };
}

describe('Admin Dashboard API (spec-based)', () => {
  let mockUsers;
  let mockCampaigns;
  let mockContributions;
  let mockReports;
  let mockWithdrawals;
  let harness;

  /**
   * Creates a valid admin token for requests.
   */
  function adminToken(overrides = {}) {
    vi.spyOn(jwt, 'verify').mockReturnValue({
      id: 'admin-id-1',
      email: 'admin@fundfrog.com',
      name: 'Admin User',
      role: 'admin',
      ...overrides,
    });
    return 'Bearer admin-jwt-token';
  }

  /**
   * Creates a valid non-admin token (supporter).
   */
  function supporterToken() {
    vi.spyOn(jwt, 'verify').mockReturnValue({
      id: 'supporter-id-1',
      email: 'supporter@test.com',
      name: 'Supporter User',
      role: 'supporter',
    });
    return 'Bearer supporter-jwt-token';
  }

  beforeEach(() => {
    vi.clearAllMocks();

    // Create mock cursors that return empty arrays by default
    mockUsers = {
      findOne: vi.fn(),
      insertOne: vi.fn(),
      updateOne: vi.fn(),
      deleteOne: vi.fn(),
      countDocuments: vi.fn(),
      aggregate: vi.fn(() => ({ toArray: vi.fn().mockResolvedValue([]) })),
      find: vi.fn(() => mockCursor([])),
    };

    mockCampaigns = {
      findOne: vi.fn(),
      find: vi.fn(() => mockCursor([])),
      updateOne: vi.fn(),
      deleteOne: vi.fn(),
      deleteMany: vi.fn(),
    };

    mockContributions = {
      find: vi.fn(() => mockCursor([])),
      deleteMany: vi.fn(),
    };

    mockReports = {
      find: vi.fn(() => mockCursor([])),
      insertOne: vi.fn(),
    };

    mockWithdrawals = {
      findOne: vi.fn(),
      find: vi.fn(() => mockCursor([])),
      updateOne: vi.fn(),
    };

    const app = createAdminApp({
      users: mockUsers,
      campaigns: mockCampaigns,
      contributions: mockContributions,
      reports: mockReports,
      withdrawals: mockWithdrawals,
    });

    harness = createTestHarness(app);
  });

  afterEach(async () => {
    await harness.stop();
    vi.restoreAllMocks();
  });

  // ═══════════════════════════════════════════════════════════════
  // GET /api/admin/stats
  // ═══════════════════════════════════════════════════════════════
  describe('GET /api/admin/stats', () => {
    it('should return platform stats for admin users', async () => {
      await harness.start();
      mockUsers.countDocuments
        .mockResolvedValueOnce(10)  // supporters
        .mockResolvedValueOnce(5);  // creators
      mockUsers.aggregate.mockReturnValue({
        toArray: vi.fn().mockResolvedValue([{ _id: null, total: 2500 }]),
      });

      const result = await harness.request('GET', '/api/admin/stats', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.stats).toEqual({
        totalSupporters: 10,
        totalCreators: 5,
        totalCredits: 2500,
        totalPayments: 0,
      });
      expect(mockUsers.countDocuments).toHaveBeenCalledWith({ role: 'supporter' });
      expect(mockUsers.countDocuments).toHaveBeenCalledWith({ role: 'creator' });
    });

    it('should return 0 totalCredits when no users exist', async () => {
      await harness.start();
      mockUsers.countDocuments.mockResolvedValue(0);
      mockUsers.aggregate.mockReturnValue({
        toArray: vi.fn().mockResolvedValue([]),
      });

      const result = await harness.request('GET', '/api/admin/stats', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.stats.totalCredits).toBe(0);
    });

    it('should return 401 without a token', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/admin/stats');
      expect(result.status).toBe(401);
      expect(result.body.message).toContain('Access denied');
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/admin/stats', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
      expect(result.body.message).toContain('Required role: admin');
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // GET /api/admin/pending-campaigns
  // ═══════════════════════════════════════════════════════════════
  describe('GET /api/admin/pending-campaigns', () => {
    it('should return pending campaigns sorted by createdAt desc', async () => {
      await harness.start();
      const pendingCampaigns = [
        { _id: 'c1', title: 'Campaign B', status: 'pending', createdAt: new Date('2025-01-02') },
        { _id: 'c2', title: 'Campaign A', status: 'pending', createdAt: new Date('2025-01-01') },
      ];
      const expectedCampaigns = [
        { _id: 'c1', title: 'Campaign B', status: 'pending', createdAt: '2025-01-02T00:00:00.000Z' },
        { _id: 'c2', title: 'Campaign A', status: 'pending', createdAt: '2025-01-01T00:00:00.000Z' },
      ];
      const cursorMock = mockCursor(pendingCampaigns);
      mockCampaigns.find.mockReturnValue(cursorMock);

      const result = await harness.request('GET', '/api/admin/pending-campaigns', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toEqual(expectedCampaigns);
      expect(mockCampaigns.find).toHaveBeenCalledWith({ status: 'pending' });
      expect(cursorMock.sort).toHaveBeenCalledWith({ createdAt: -1 });
    });

    it('should return empty array when no pending campaigns exist', async () => {
      await harness.start();
      mockCampaigns.find.mockReturnValue(mockCursor([]));

      const result = await harness.request('GET', '/api/admin/pending-campaigns', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.campaigns).toEqual([]);
    });

    it('should return 401 without a token', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/admin/pending-campaigns');
      expect(result.status).toBe(401);
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/admin/pending-campaigns', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // PATCH /api/campaigns/:id/approve
  // ═══════════════════════════════════════════════════════════════
  describe('PATCH /api/campaigns/:id/approve', () => {
    it('should approve a pending campaign', async () => {
      await harness.start();
      const pendingCampaign = { _id: 'camp-1', title: 'Test Campaign', status: 'pending' };
      const approvedCampaign = { ...pendingCampaign, status: 'approved' };

      mockCampaigns.findOne
        .mockResolvedValueOnce(pendingCampaign)  // first findOne (check exists + pending)
        .mockResolvedValueOnce(approvedCampaign); // second findOne (return updated)

      const result = await harness.request('PATCH', '/api/campaigns/camp-1/approve', {}, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.campaign.status).toBe('approved');
      expect(mockCampaigns.updateOne).toHaveBeenCalledWith(
        { _id: 'camp-1' },
        { $set: { status: 'approved' } },
      );
    });

    it('should return 404 when campaign does not exist', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue(null);

      const result = await harness.request('PATCH', '/api/campaigns/nonexistent/approve', {}, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Campaign not found');
    });

    it('should return 400 when campaign is not pending', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue({ _id: 'camp-1', status: 'approved' });

      const result = await harness.request('PATCH', '/api/campaigns/camp-1/approve', {}, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Only pending campaigns');
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('PATCH', '/api/campaigns/camp-1/approve', {}, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // PATCH /api/campaigns/:id/reject
  // ═══════════════════════════════════════════════════════════════
  describe('PATCH /api/campaigns/:id/reject', () => {
    it('should reject a pending campaign', async () => {
      await harness.start();
      const pendingCampaign = { _id: 'camp-2', title: 'Reject Me', status: 'pending' };
      const rejectedCampaign = { ...pendingCampaign, status: 'rejected' };

      mockCampaigns.findOne
        .mockResolvedValueOnce(pendingCampaign)
        .mockResolvedValueOnce(rejectedCampaign);

      const result = await harness.request('PATCH', '/api/campaigns/camp-2/reject', {}, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.campaign.status).toBe('rejected');
      expect(mockCampaigns.updateOne).toHaveBeenCalledWith(
        { _id: 'camp-2' },
        { $set: { status: 'rejected' } },
      );
    });

    it('should return 400 when campaign is already approved', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue({ _id: 'camp-2', status: 'approved' });

      const result = await harness.request('PATCH', '/api/campaigns/camp-2/reject', {}, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Only pending campaigns');
    });

    it('should return 404 when campaign does not exist', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue(null);

      const result = await harness.request('PATCH', '/api/campaigns/nonexistent/reject', {}, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(404);
    });

    it('should return 401 without a token', async () => {
      await harness.start();
      const result = await harness.request('PATCH', '/api/campaigns/camp-2/reject', {});
      expect(result.status).toBe(401);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // GET /api/admin/pending-withdrawals
  // ═══════════════════════════════════════════════════════════════
  describe('GET /api/admin/pending-withdrawals', () => {
    it('should return pending withdrawals sorted by date desc', async () => {
      await harness.start();
      const pendingWithdrawals = [
        { _id: 'w1', creatorEmail: 'c1@test.com', status: 'pending', withdrawalCredit: 200, date: new Date('2025-02-02') },
        { _id: 'w2', creatorEmail: 'c2@test.com', status: 'pending', withdrawalCredit: 100, date: new Date('2025-02-01') },
      ];
      const expectedWithdrawals = [
        { _id: 'w1', creatorEmail: 'c1@test.com', status: 'pending', withdrawalCredit: 200, date: '2025-02-02T00:00:00.000Z' },
        { _id: 'w2', creatorEmail: 'c2@test.com', status: 'pending', withdrawalCredit: 100, date: '2025-02-01T00:00:00.000Z' },
      ];
      const cursorMock = mockCursor(pendingWithdrawals);
      mockWithdrawals.find.mockReturnValue(cursorMock);

      const result = await harness.request('GET', '/api/admin/pending-withdrawals', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.withdrawals).toEqual(expectedWithdrawals);
      expect(mockWithdrawals.find).toHaveBeenCalledWith({ status: 'pending' });
      expect(cursorMock.sort).toHaveBeenCalledWith({ date: -1 });
    });

    it('should return empty array when no pending withdrawals', async () => {
      await harness.start();
      mockWithdrawals.find.mockReturnValue(mockCursor([]));

      const result = await harness.request('GET', '/api/admin/pending-withdrawals', undefined, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(200);
      expect(result.body.withdrawals).toEqual([]);
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/admin/pending-withdrawals', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // PATCH /api/withdrawals/:id/approve
  // ═══════════════════════════════════════════════════════════════
  describe('PATCH /api/withdrawals/:id/approve', () => {
    it('should approve a pending withdrawal', async () => {
      await harness.start();
      const pending = { _id: 'w1', creatorEmail: 'creator@test.com', status: 'pending', withdrawalCredit: 200 };
      const approved = { ...pending, status: 'approved' };

      mockWithdrawals.findOne
        .mockResolvedValueOnce(pending)
        .mockResolvedValueOnce(approved);

      const result = await harness.request('PATCH', '/api/withdrawals/w1/approve', {}, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.withdrawal.status).toBe('approved');
      expect(mockWithdrawals.updateOne).toHaveBeenCalledWith(
        { _id: 'w1' },
        { $set: { status: 'approved' } },
      );
    });

    it('should return 404 when withdrawal does not exist', async () => {
      await harness.start();
      mockWithdrawals.findOne.mockResolvedValue(null);

      const result = await harness.request('PATCH', '/api/withdrawals/nonexistent/approve', {}, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Withdrawal not found');
    });

    it('should return 400 when withdrawal is not pending', async () => {
      await harness.start();
      mockWithdrawals.findOne.mockResolvedValue({ _id: 'w1', status: 'approved' });

      const result = await harness.request('PATCH', '/api/withdrawals/w1/approve', {}, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Only pending withdrawals');
    });

    it('should return 401 without a token', async () => {
      await harness.start();
      const result = await harness.request('PATCH', '/api/withdrawals/w1/approve', {});
      expect(result.status).toBe(401);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // GET /api/users
  // ═══════════════════════════════════════════════════════════════
  describe('GET /api/users', () => {
    it('should return all users without password field', async () => {
      await harness.start();
      const usersData = [
        { _id: { toString: () => 'u1' }, name: 'Alice', email: 'alice@test.com', photoURL: '', role: 'supporter', credits: 50, createdAt: new Date('2025-01-01') },
        { _id: { toString: () => 'u2' }, name: 'Bob', email: 'bob@test.com', photoURL: 'http://pic.com/bob.jpg', role: 'creator', credits: 20, createdAt: new Date('2025-01-02') },
      ];
      const cursorMock = mockCursor(usersData);
      mockUsers.find.mockReturnValue(cursorMock);

      const result = await harness.request('GET', '/api/users', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.users).toHaveLength(2);
      expect(result.body.users[0].name).toBe('Alice');
      expect(result.body.users[1].name).toBe('Bob');
      // Ensure password is excluded
      expect(result.body.users[0].password).toBeUndefined();
      expect(cursorMock.project).toHaveBeenCalledWith({ password: 0 });
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/users', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // PATCH /api/users/:id
  // ═══════════════════════════════════════════════════════════════
  describe('PATCH /api/users/:id', () => {
    it('should update a user role', async () => {
      await harness.start();
      const existingUser = { _id: { toString: () => 'u1' }, name: 'Alice', email: 'alice@test.com', role: 'supporter', credits: 50, photoURL: '' };
      const updatedUser = { ...existingUser, role: 'creator' };

      mockUsers.findOne
        .mockResolvedValueOnce(existingUser)
        .mockResolvedValueOnce(updatedUser);

      const result = await harness.request('PATCH', '/api/users/u1', { role: 'creator' }, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.user.role).toBe('creator');
      expect(mockUsers.updateOne).toHaveBeenCalledWith(
        { _id: 'u1' },
        { $set: { role: 'creator' } },
      );
    });

    it('should return 400 for invalid role value', async () => {
      await harness.start();
      const result = await harness.request('PATCH', '/api/users/u1', { role: 'superadmin' }, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Role must be');
    });

    it('should return 400 when role is missing', async () => {
      await harness.start();
      const result = await harness.request('PATCH', '/api/users/u1', {}, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Role must be');
    });

    it('should return 404 when user does not exist', async () => {
      await harness.start();
      mockUsers.findOne.mockResolvedValue(null);

      const result = await harness.request('PATCH', '/api/users/nonexistent', { role: 'creator' }, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(404);
      expect(result.body.message).toContain('User not found');
    });

    it('should return 403 for non-admin', async () => {
      await harness.start();
      const result = await harness.request('PATCH', '/api/users/u1', { role: 'creator' }, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // DELETE /api/users/:id
  // ═══════════════════════════════════════════════════════════════
  describe('DELETE /api/users/:id', () => {
    it('should delete a non-admin user', async () => {
      await harness.start();
      mockUsers.findOne.mockResolvedValue({ _id: 'u1', name: 'Alice', role: 'supporter' });
      mockUsers.countDocuments.mockResolvedValue(5);

      const result = await harness.request('DELETE', '/api/users/u1', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('User deleted');
      expect(mockUsers.deleteOne).toHaveBeenCalledWith({ _id: 'u1' });
    });

    it('should prevent deleting the last admin', async () => {
      await harness.start();
      mockUsers.findOne.mockResolvedValue({ _id: 'admin-1', name: 'Solo Admin', role: 'admin' });
      mockUsers.countDocuments.mockResolvedValue(1);

      const result = await harness.request('DELETE', '/api/users/admin-1', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(400);
      expect(result.body.message).toContain('Cannot delete the last admin');
      expect(mockUsers.deleteOne).not.toHaveBeenCalled();
    });

    it('should allow deleting an admin when other admins exist', async () => {
      await harness.start();
      mockUsers.findOne.mockResolvedValue({ _id: 'admin-2', name: 'Admin Two', role: 'admin' });
      mockUsers.countDocuments.mockResolvedValue(3);

      const result = await harness.request('DELETE', '/api/users/admin-2', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(mockUsers.deleteOne).toHaveBeenCalled();
    });

    it('should return 404 when user does not exist', async () => {
      await harness.start();
      mockUsers.findOne.mockResolvedValue(null);

      const result = await harness.request('DELETE', '/api/users/nonexistent', undefined, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(404);
    });

    it('should return 403 for non-admin', async () => {
      await harness.start();
      const result = await harness.request('DELETE', '/api/users/u1', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // DELETE /api/campaigns/:id/admin
  // ═══════════════════════════════════════════════════════════════
  describe('DELETE /api/campaigns/:id/admin', () => {
    it('should delete any campaign and refund approved supporters', async () => {
      await harness.start();
      const campaign = { _id: 'camp-1', title: 'Any Campaign', creatorEmail: 'creator@test.com' };
      const approvedContributions = [
        { supporterEmail: 'sup1@test.com', amount: 100 },
        { supporterEmail: 'sup2@test.com', amount: 50 },
      ];

      mockCampaigns.findOne.mockResolvedValue(campaign);
      mockContributions.find.mockReturnValue(mockCursor(approvedContributions));

      const result = await harness.request('DELETE', '/api/campaigns/camp-1/admin', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.message).toContain('Campaign deleted and supporters refunded');
      // Verify refunds were issued to each supporter
      expect(mockUsers.updateOne).toHaveBeenCalledTimes(2);
      expect(mockUsers.updateOne).toHaveBeenCalledWith(
        { email: 'sup1@test.com' },
        { $inc: { credits: 100 } },
      );
      expect(mockUsers.updateOne).toHaveBeenCalledWith(
        { email: 'sup2@test.com' },
        { $inc: { credits: 50 } },
      );
      expect(mockContributions.deleteMany).toHaveBeenCalledWith({ campaignId: 'camp-1' });
      expect(mockCampaigns.deleteOne).toHaveBeenCalledWith({ _id: 'camp-1' });
    });

    it('should delete campaign with no contributions (no refunds needed)', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue({ _id: 'camp-2', title: 'Empty Campaign' });
      mockContributions.find.mockReturnValue(mockCursor([]));

      const result = await harness.request('DELETE', '/api/campaigns/camp-2/admin', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(mockUsers.updateOne).not.toHaveBeenCalled();
      expect(mockContributions.deleteMany).toHaveBeenCalled();
    });

    it('should return 404 when campaign does not exist', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue(null);

      const result = await harness.request('DELETE', '/api/campaigns/nonexistent/admin', undefined, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(404);
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('DELETE', '/api/campaigns/camp-1/admin', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // GET /api/reports
  // ═══════════════════════════════════════════════════════════════
  describe('GET /api/reports', () => {
    it('should return all reports sorted by date desc', async () => {
      await harness.start();
      const reportsData = [
        { _id: 'r1', reporterEmail: 'a@test.com', campaignTitle: 'Bad Campaign', reason: 'Scam', date: new Date('2025-03-02') },
        { _id: 'r2', reporterEmail: 'b@test.com', campaignTitle: 'Another', reason: 'Spam', date: new Date('2025-03-01') },
      ];
      const expectedReports = [
        { _id: 'r1', reporterEmail: 'a@test.com', campaignTitle: 'Bad Campaign', reason: 'Scam', date: '2025-03-02T00:00:00.000Z' },
        { _id: 'r2', reporterEmail: 'b@test.com', campaignTitle: 'Another', reason: 'Spam', date: '2025-03-01T00:00:00.000Z' },
      ];
      const cursorMock = mockCursor(reportsData);
      mockReports.find.mockReturnValue(cursorMock);

      const result = await harness.request('GET', '/api/reports', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.reports).toEqual(expectedReports);
      expect(cursorMock.sort).toHaveBeenCalledWith({ date: -1 });
    });

    it('should return empty array when no reports', async () => {
      await harness.start();
      mockReports.find.mockReturnValue(mockCursor([]));

      const result = await harness.request('GET', '/api/reports', undefined, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(200);
      expect(result.body.reports).toEqual([]);
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('GET', '/api/reports', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // POST /api/reports
  // ═══════════════════════════════════════════════════════════════
  describe('POST /api/reports', () => {
    it('should create a report for any logged-in user', async () => {
      await harness.start();
      const insertedId = 'report-1';
      mockReports.insertOne.mockResolvedValue({ insertedId });

      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'any-user-id',
        email: 'loggedin@test.com',
        name: 'Logged In User',
        role: 'supporter',
      });

      const result = await harness.request('POST', '/api/reports', {
        campaignId: 'camp-1',
        campaignTitle: 'Suspicious Campaign',
        reason: 'This appears to be fraudulent.',
      }, {
        Authorization: 'Bearer any-valid-token',
      });

      expect(result.status).toBe(201);
      expect(result.body.report).toBeDefined();
      expect(result.body.report.reporterEmail).toBe('loggedin@test.com');
      expect(result.body.report.campaignTitle).toBe('Suspicious Campaign');
      expect(result.body.report.campaignId).toBe('camp-1');
      expect(result.body.report.reason).toBe('This appears to be fraudulent.');
      expect(result.body.report.date).toBeDefined();
      expect(mockReports.insertOne).toHaveBeenCalledOnce();
    });

    it('should use the authenticated user email as reporterEmail', async () => {
      await harness.start();
      // Use a supporter token with known email
      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'sup-1',
        email: 'supporter@test.com',
        name: 'Test Supporter',
        role: 'supporter',
      });
      mockReports.insertOne.mockResolvedValue({ insertedId: 'report-2' });

      const result = await harness.request('POST', '/api/reports', {
        campaignId: 'camp-1',
        campaignTitle: 'Bad Campaign',
        reason: 'Spam content',
      }, {
        Authorization: 'Bearer supporter-jwt',
      });

      expect(result.status).toBe(201);
      expect(result.body.report.reporterEmail).toBe('supporter@test.com');

      const insertedReport = mockReports.insertOne.mock.calls[0][0];
      expect(insertedReport.reporterEmail).toBe('supporter@test.com');
    });

    it('should return 400 when required fields are missing', async () => {
      await harness.start();
      const result1 = await harness.request('POST', '/api/reports', {
        campaignTitle: 'Title only',
      }, {
        Authorization: adminToken(),
      });
      expect(result1.status).toBe(400);
      expect(result1.body.message).toContain('required');

      const result2 = await harness.request('POST', '/api/reports', {}, {
        Authorization: adminToken(),
      });
      expect(result2.status).toBe(400);
      expect(result2.body.message).toContain('required');
    });

    it('should allow any logged-in role (supporter/creator/admin) to report', async () => {
      await harness.start();
      mockReports.insertOne.mockResolvedValue({ insertedId: 'report-3' });

      // Creator reports
      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'creator-1', email: 'creator@test.com', name: 'Creator', role: 'creator',
      });
      const result1 = await harness.request('POST', '/api/reports', {
        campaignId: 'c1', campaignTitle: 'Campaign', reason: 'Bad',
      }, { Authorization: 'Bearer creator-jwt' });
      expect(result1.status).toBe(201);

      // Supporter reports
      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'sup-1', email: 'sup@test.com', name: 'Supporter', role: 'supporter',
      });
      const result2 = await harness.request('POST', '/api/reports', {
        campaignId: 'c2', campaignTitle: 'Campaign 2', reason: 'Spam',
      }, { Authorization: 'Bearer supporter-jwt' });
      expect(result2.status).toBe(201);

      // Admin reports
      vi.spyOn(jwt, 'verify').mockReturnValue({
        id: 'admin-1', email: 'admin@test.com', name: 'Admin', role: 'admin',
      });
      const result3 = await harness.request('POST', '/api/reports', {
        campaignId: 'c3', campaignTitle: 'Campaign 3', reason: 'Fraud',
      }, { Authorization: 'Bearer admin-jwt' });
      expect(result3.status).toBe(201);
    });

    it('should return 401 without a token', async () => {
      await harness.start();
      const result = await harness.request('POST', '/api/reports', {
        campaignId: 'c1', campaignTitle: 'T', reason: 'R',
      });
      expect(result.status).toBe(401);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  // DELETE /api/campaigns/:id/suspend
  // ═══════════════════════════════════════════════════════════════
  describe('DELETE /api/campaigns/:id/suspend', () => {
    it('should suspend a campaign', async () => {
      await harness.start();
      const campaign = { _id: 'camp-1', title: 'Active Campaign', status: 'approved' };
      const suspended = { ...campaign, status: 'suspended' };

      mockCampaigns.findOne
        .mockResolvedValueOnce(campaign)
        .mockResolvedValueOnce(suspended);

      const result = await harness.request('DELETE', '/api/campaigns/camp-1/suspend', undefined, {
        Authorization: adminToken(),
      });

      expect(result.status).toBe(200);
      expect(result.body.campaign.status).toBe('suspended');
      expect(mockCampaigns.updateOne).toHaveBeenCalledWith(
        { _id: 'camp-1' },
        { $set: { status: 'suspended' } },
      );
    });

    it('should return 404 when campaign does not exist', async () => {
      await harness.start();
      mockCampaigns.findOne.mockResolvedValue(null);

      const result = await harness.request('DELETE', '/api/campaigns/nonexistent/suspend', undefined, {
        Authorization: adminToken(),
      });
      expect(result.status).toBe(404);
      expect(result.body.message).toContain('Campaign not found');
    });

    it('should return 403 for non-admin users', async () => {
      await harness.start();
      const result = await harness.request('DELETE', '/api/campaigns/camp-1/suspend', undefined, {
        Authorization: supporterToken(),
      });
      expect(result.status).toBe(403);
    });

    it('should return 401 without a token', async () => {
      await harness.start();
      const result = await harness.request('DELETE', '/api/campaigns/camp-1/suspend');
      expect(result.status).toBe(401);
    });
  });
});
