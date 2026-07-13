const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { toNodeHandler, fromNodeHeaders } = require('better-auth/node');
const { createAuth } = require('./auth');

dotenv.config();

const uri = process.env.MONGOBD_URI;
const app = express();
const port = process.env.PORT || 9000;

app.use(
  cors({
    origin: process.env.BETTER_AUTH_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-key'],
  }),
);

const mongoClient = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const auth = createAuth(mongoClient.db('fundfrog'));

// Better Auth must be mounted before express.json()
app.all('/api/auth/{*any}', toNodeHandler(auth));

app.use(express.json());

let db;
let users;
let campaigns;
let contributions;
let reports;
let withdrawals;
let payments;
let notifications;

async function run() {
  try {
    await mongoClient.connect();
    console.log('Successfully connected to MongoDB!');
    db = mongoClient.db('fundfrog');
    users = db.collection('users');
    campaigns = db.collection('campaigns');
    contributions = db.collection('contributions');
    reports = db.collection('reports');
    withdrawals = db.collection('withdrawals');
    payments = db.collection('payments');
    notifications = db.collection('notifications');
  } finally {
    // await mongoClient.close();
  }
}

const dbReady = run();
dbReady.catch(console.dir);

// Wait for DB before processing any route
app.use(async (req, res, next) => {
  try {
    await dbReady;
    next();
  } catch {
    res.status(500).json({ message: 'Database connection failed.' });
  }
});

async function verifyToken(req, res, next) {
  try {
    const headers = fromNodeHeaders(req.headers);
    const session = await auth.api.getSession({ headers });
    if (session) {
      req.user = session.user;
      return next();
    }
  } catch (err) {
    console.error('Auth error:', err);
  }
  return res.status(401).json({ message: 'Access denied. No token provided.' });
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

// ─── Campaign routes ────────────────────────────────────────────────

app.get('/api/campaigns', async (req, res) => {
  try {
    const { top_funded, category, status, search, creatorEmail } = req.query;
    const filter = {};

    if (category) filter.category = category;
    if (status) filter.status = status;
    else if (!creatorEmail) filter.status = 'approved';
    if (creatorEmail) filter.creatorEmail = creatorEmail;

    if (search) {
      filter.title = { $regex: search, $options: 'i' };
    }

    let cursor = campaigns.find(filter);

    if (top_funded) {
      cursor = cursor.sort({ amountRaised: -1 }).limit(6);
    }

    const results = await cursor.toArray();
    res.json({ campaigns: results });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/campaigns/:id', async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    if (!campaign) {
      return res.status(404).json({ message: 'Campaign not found.' });
    }
    res.json({ campaign });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/api/campaigns', verifyToken, requireRole('creator'), async (req, res) => {
  try {
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

    const result = await campaigns.insertOne(campaign);
    const saved = { ...campaign, _id: result.insertedId };

    res.status(201).json({ campaign: saved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.put('/api/campaigns/:id', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
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

    await campaigns.updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
    const updated = await campaigns.findOne({ _id: new ObjectId(req.params.id) });

    res.json({ campaign: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.delete('/api/campaigns/:id', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    if (!campaign) {
      return res.status(404).json({ message: 'Campaign not found.' });
    }
    if (campaign.creatorEmail !== req.user.email) {
      return res.status(403).json({ message: 'You can only delete your own campaigns.' });
    }

    // Refund all approved supporters
    const approvedContributions = await contributions.find({ campaignId: req.params.id, status: 'approved' }).toArray();
    for (const c of approvedContributions) {
      await users.updateOne({ email: c.supporterEmail }, { $inc: { credits: c.amount } });
    }
    await contributions.deleteMany({ campaignId: req.params.id });
    await campaigns.deleteOne({ _id: new ObjectId(req.params.id) });

    res.json({ message: 'Campaign deleted and supporters refunded.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Creator routes ───────────────────────────────────────────

app.get('/api/creator/stats', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const creatorCampaigns = await campaigns.find({ creatorEmail: req.user.email }).toArray();
    const totalCampaigns = creatorCampaigns.length;
    const now = new Date();
    const activeCampaigns = creatorCampaigns.filter(
      (c) => c.status === 'approved' && new Date(c.deadline) > now,
    ).length;
    const totalRaised = creatorCampaigns.reduce((sum, c) => sum + (c.amountRaised || 0), 0);

    res.json({ stats: { totalCampaigns, activeCampaigns, totalRaised } });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/creator/pending-contributions', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const pending = await contributions
      .find({ creatorEmail: req.user.email, status: 'pending' })
      .sort({ date: -1 })
      .toArray();

    res.json({ contributions: pending });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/contributions/:id/approve', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const contribution = await contributions.findOne({ _id: new ObjectId(req.params.id) });
    if (!contribution) {
      return res.status(404).json({ message: 'Contribution not found.' });
    }
    if (contribution.creatorEmail !== req.user.email) {
      return res.status(403).json({ message: 'This contribution does not belong to your campaign.' });
    }
    if (contribution.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending contributions can be approved.' });
    }

    await contributions.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'approved' } },
    );

    await campaigns.updateOne(
      { _id: new ObjectId(contribution.campaignId) },
      { $inc: { amountRaised: contribution.amount } },
    );

    await notifications.insertOne({
      message: `Your contribution of ${contribution.amount} credits to ${contribution.campaignTitle} was approved`,
      toEmail: contribution.supporterEmail,
      fromEmail: req.user.email,
      actionRoute: '/dashboard/supporter/my-contributions',
      read: false,
      createdAt: new Date(),
    });

    const updated = await contributions.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ contribution: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/contributions/:id/reject', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const contribution = await contributions.findOne({ _id: new ObjectId(req.params.id) });
    if (!contribution) {
      return res.status(404).json({ message: 'Contribution not found.' });
    }
    if (contribution.creatorEmail !== req.user.email) {
      return res.status(403).json({ message: 'This contribution does not belong to your campaign.' });
    }
    if (contribution.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending contributions can be rejected.' });
    }

    // Refund credits to supporter
    await users.updateOne(
      { email: contribution.supporterEmail },
      { $inc: { credits: contribution.amount } },
    );

    await contributions.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'rejected' } },
    );

    await notifications.insertOne({
      message: `Your contribution of ${contribution.amount} credits to ${contribution.campaignTitle} was rejected`,
      toEmail: contribution.supporterEmail,
      fromEmail: req.user.email,
      actionRoute: '/dashboard/supporter/my-contributions',
      read: false,
      createdAt: new Date(),
    });

    const updated = await contributions.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ contribution: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Supporter routes ──────────────────────────────────────────

app.get('/api/supporter/stats', verifyToken, requireRole('supporter'), async (req, res) => {
  try {
    const allContributions = await contributions.find({ supporterEmail: req.user.email }).toArray();
    const totalContributions = allContributions.length;
    const pendingCount = allContributions.filter((c) => c.status === 'pending').length;
    const approvedAmount = allContributions
      .filter((c) => c.status === 'approved')
      .reduce((sum, c) => sum + (c.amount || 0), 0);

    res.json({ stats: { totalContributions, pendingCount, approvedAmount } });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/supporter/approved-contributions', verifyToken, requireRole('supporter'), async (req, res) => {
  try {
    const approved = await contributions
      .find({ supporterEmail: req.user.email, status: 'approved' })
      .sort({ date: -1 })
      .toArray();

    res.json({ contributions: approved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/api/contributions', verifyToken, requireRole('supporter'), async (req, res) => {
  try {
    const { campaignId, amount } = req.body;
    if (!campaignId || !amount) {
      return res.status(400).json({ message: 'Campaign ID and amount are required.' });
    }

    const campaign = await campaigns.findOne({ _id: new ObjectId(campaignId) });
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

    const user = await users.findOne({ email: req.user.email });
    if (!user || user.credits < contributionAmount) {
      return res.status(400).json({ message: 'Insufficient credits.' });
    }

    await users.updateOne({ email: req.user.email }, { $inc: { credits: -contributionAmount } });

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

    const result = await contributions.insertOne(contribution);
    const saved = { ...contribution, _id: result.insertedId };

    await notifications.insertOne({
      message: `${req.user.name} contributed ${contributionAmount} credits to ${campaign.title}`,
      toEmail: campaign.creatorEmail,
      fromEmail: req.user.email,
      actionRoute: '/dashboard/creator',
      read: false,
      createdAt: new Date(),
    });

    res.status(201).json({ contribution: saved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/contributions', verifyToken, requireRole('supporter'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const filter = { supporterEmail: req.user.email };

    const total = await contributions.countDocuments(filter);
    const items = await contributions
      .find(filter)
      .sort({ date: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.json({
      contributions: items,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Payment verify (internal, called by Next.js Route Handler) ──

app.post('/api/payments/verify', async (req, res) => {
  try {
    const key = req.headers['x-internal-key'];
    if (key !== process.env.INTERNAL_API_KEY) {
      return res.status(401).json({ message: 'Unauthorized.' });
    }

    const { stripeSessionId, credits, email, name, amountPaid } = req.body;

    await payments.insertOne({
      email,
      name,
      creditsPurchased: credits,
      amountPaid,
      stripeSessionId,
      date: new Date(),
    });

    await users.updateOne({ email }, { $inc: { credits } });

    res.json({ success: true });
  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/payments', verifyToken, async (req, res) => {
  try {
    const items = await payments
      .find({ email: req.user.email })
      .sort({ date: -1 })
      .toArray();
    res.json({ payments: items });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Admin routes ──────────────────────────────────────────────

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

app.get('/api/admin/pending-campaigns', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const pending = await campaigns.find({ status: 'pending' }).sort({ createdAt: -1 }).toArray();
    res.json({ campaigns: pending });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/campaigns/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    if (!campaign) {
      return res.status(404).json({ message: 'Campaign not found.' });
    }
    if (campaign.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending campaigns can be approved.' });
    }

    await campaigns.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'approved' } },
    );

    await notifications.insertOne({
      message: `Your campaign ${campaign.title} has been approved`,
      toEmail: campaign.creatorEmail,
      fromEmail: req.user.email,
      actionRoute: '/dashboard/creator/my-campaigns',
      read: false,
      createdAt: new Date(),
    });

    const updated = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ campaign: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/campaigns/:id/reject', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    if (!campaign) {
      return res.status(404).json({ message: 'Campaign not found.' });
    }
    if (campaign.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending campaigns can be rejected.' });
    }

    await campaigns.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'rejected' } },
    );

    await notifications.insertOne({
      message: `Your campaign ${campaign.title} has been rejected`,
      toEmail: campaign.creatorEmail,
      fromEmail: req.user.email,
      actionRoute: '/dashboard/creator/my-campaigns',
      read: false,
      createdAt: new Date(),
    });

    const updated = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ campaign: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/admin/pending-withdrawals', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const pending = await withdrawals.find({ status: 'pending' }).sort({ date: -1 }).toArray();
    res.json({ withdrawals: pending });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/withdrawals/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const withdrawal = await withdrawals.findOne({ _id: new ObjectId(req.params.id) });
    if (!withdrawal) {
      return res.status(404).json({ message: 'Withdrawal not found.' });
    }
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending withdrawals can be approved.' });
    }

    await withdrawals.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'approved' } },
    );

    await notifications.insertOne({
      message: `Your withdrawal of ${withdrawal.withdrawalCredit} credits has been approved`,
      toEmail: withdrawal.creatorEmail,
      fromEmail: req.user.email,
      actionRoute: '/dashboard/creator/withdrawals',
      read: false,
      createdAt: new Date(),
    });

    const updated = await withdrawals.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ withdrawal: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Creator withdrawal routes ─────────────────────────────────────

app.post('/api/withdrawals', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const { credits, paymentSystem, accountNumber } = req.body;
    if (!credits || !paymentSystem || !accountNumber) {
      return res.status(400).json({ message: 'Credits, payment system, and account number are required.' });
    }
    const withdrawalCredits = Number(credits);
    if (withdrawalCredits < 200) {
      return res.status(400).json({ message: 'Minimum withdrawal is 200 credits.' });
    }
    if (!['bkash', 'nagad', 'bank'].includes(paymentSystem)) {
      return res.status(400).json({ message: 'Payment system must be "bkash", "nagad", or "bank".' });
    }
    const user = await users.findOne({ email: req.user.email });
    if (!user || user.credits < withdrawalCredits) {
      return res.status(400).json({ message: 'Insufficient credits.' });
    }

    await users.updateOne({ email: req.user.email }, { $inc: { credits: -withdrawalCredits } });

    const withdrawalAmount = (withdrawalCredits / 20).toFixed(2);
    const withdrawal = {
      creatorEmail: req.user.email,
      creatorName: req.user.name,
      withdrawalCredit: withdrawalCredits,
      withdrawalAmount: Number(withdrawalAmount),
      paymentSystem,
      accountNumber,
      date: new Date(),
      status: 'pending',
    };

    const result = await withdrawals.insertOne(withdrawal);
    const saved = { ...withdrawal, _id: result.insertedId };

    await notifications.insertOne({
      message: `${req.user.name} requested a withdrawal of ${withdrawalCredits} credits`,
      toEmail: 'admin',
      fromEmail: req.user.email,
      actionRoute: '/dashboard/admin/withdrawal-requests',
      read: false,
      createdAt: new Date(),
    });

    res.status(201).json({ withdrawal: saved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/withdrawals', verifyToken, requireRole('creator'), async (req, res) => {
  try {
    const items = await withdrawals
      .find({ creatorEmail: req.user.email })
      .sort({ date: -1 })
      .toArray();
    res.json({ withdrawals: items });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

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

app.patch('/api/users/:id', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const { role } = req.body;
    if (!role || !['supporter', 'creator', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Role must be "supporter", "creator", or "admin".' });
    }

    const user = await users.findOne({ _id: new ObjectId(req.params.id) });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    await users.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role } },
    );

    const updated = await users.findOne({ _id: new ObjectId(req.params.id) });
    res.json({
      user: {
        id: updated._id.toString(),
        name: updated.name,
        email: updated.email,
        photoURL: updated.photoURL || '',
        role: updated.role,
        credits: updated.credits,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.delete('/api/users/:id', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const user = await users.findOne({ _id: new ObjectId(req.params.id) });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const adminCount = await users.countDocuments({ role: 'admin' });
    if (adminCount <= 1 && user.role === 'admin') {
      return res.status(400).json({ message: 'Cannot delete the last admin.' });
    }

    await users.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ message: 'User deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.delete('/api/campaigns/:id/admin', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    if (!campaign) {
      return res.status(404).json({ message: 'Campaign not found.' });
    }

    const approvedContributions = await contributions.find({ campaignId: req.params.id, status: 'approved' }).toArray();
    for (const c of approvedContributions) {
      await users.updateOne({ email: c.supporterEmail }, { $inc: { credits: c.amount } });
    }
    await contributions.deleteMany({ campaignId: req.params.id });
    await campaigns.deleteOne({ _id: new ObjectId(req.params.id) });

    res.json({ message: 'Campaign deleted and supporters refunded.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/reports', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const allReports = await reports.find({}).sort({ date: -1 }).toArray();
    res.json({ reports: allReports });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

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

app.delete('/api/campaigns/:id/suspend', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const campaign = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    if (!campaign) {
      return res.status(404).json({ message: 'Campaign not found.' });
    }

    await campaigns.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'suspended' } },
    );

    const updated = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ campaign: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Notification routes ──────────────────────────────────────────

app.get('/api/notifications', verifyToken, async (req, res) => {
  try {
    const items = await notifications
      .find({ toEmail: req.user.email })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();
    res.json({ notifications: items });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/notifications/:id/read', verifyToken, async (req, res) => {
  try {
    const notification = await notifications.findOne({ _id: new ObjectId(req.params.id) });
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found.' });
    }
    if (notification.toEmail !== req.user.email) {
      return res.status(403).json({ message: 'Access denied.' });
    }
    await notifications.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { read: true } },
    );
    const updated = await notifications.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ notification: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});
    
app.get('/', (req, res) => {
  res.send('This is home page of client server.');
});

app.use((req, res) => {
  res.status(404).json({ message: `Route ${req.originalUrl} not found` });
});

if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
}

module.exports = app;
     