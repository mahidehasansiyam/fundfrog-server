const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

dotenv.config();

const uri = process.env.MONGOBD_URI;
const app = express();
const port = process.env.PORT || 9000;
const JWT_SECRET = process.env.JWT_SECRET || 'fundfrog_jwt_secret_dev';

app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-internal-key'],
  }),
);

app.use(express.json());
app.use(cookieParser());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;
let users;
let campaigns;
let contributions;
let reports;
let withdrawals;
let payments;

async function run() {
  try {
    await client.connect();
    console.log('Successfully connected to MongoDB!');
    db = client.db('fundfrog');
    users = db.collection('users');
    campaigns = db.collection('campaigns');
    contributions = db.collection('contributions');
    reports = db.collection('reports');
    withdrawals = db.collection('withdrawals');
    payments = db.collection('payments');
  } finally {
    // await client.close();
  }
}

run().catch(console.dir);

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: false,
  sameSite: 'lax',
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), email: user.email, name: user.name, role: user.role },
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

function sanitizeUser(user) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    photoURL: user.photoURL || '',
    role: user.role,
    credits: user.credits,
  };
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, photoURL } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: 'Name, email, password, and role are required.' });
    }
    if (!['supporter', 'creator'].includes(role)) {
      return res.status(400).json({ message: 'Role must be "supporter" or "creator".' });
    }
    const existing = await users.findOne({ email });
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
    const result = await users.insertOne(user);
    const savedUser = { ...user, _id: result.insertedId };
    const token = signToken(savedUser);
    setTokenCookie(res, token);
    res.status(201).json({ user: sanitizeUser(savedUser) });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const user = await users.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }
    const token = signToken(user);
    setTokenCookie(res, token);
    res.json({ user: sanitizeUser(user) });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

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
    let user = await users.findOne({ email });
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
      const result = await users.insertOne(newUser);
      user = { ...newUser, _id: result.insertedId };
    }
    const token = signToken(user);
    setTokenCookie(res, token);
    res.json({ user: sanitizeUser(user) });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await users.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json({ user: sanitizeUser(user) });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearTokenCookie(res);
  res.json({ message: 'Logged out successfully.' });
});

// ─── Campaign routes ────────────────────────────────────────────────

app.get('/api/campaigns', async (req, res) => {
  try {
    const { top_funded, category, status, search, creatorEmail } = req.query;
    const filter = {};

    if (category) filter.category = category;
    if (status) filter.status = status;
    else filter.status = 'approved';
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

    const result = await campaigns.insertOne(campaign);
    const saved = { ...campaign, _id: result.insertedId };

    res.status(201).json({ campaign: saved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.put('/api/campaigns/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'creator') {
      return res.status(403).json({ message: 'Only creators can update campaigns.' });
    }

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

app.delete('/api/campaigns/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'creator') {
      return res.status(403).json({ message: 'Only creators can delete campaigns.' });
    }

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

app.get('/api/creator/stats', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'creator') {
      return res.status(403).json({ message: 'Access denied. Creators only.' });
    }

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

app.get('/api/creator/pending-contributions', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'creator') {
      return res.status(403).json({ message: 'Access denied. Creators only.' });
    }

    const pending = await contributions
      .find({ creatorEmail: req.user.email, status: 'pending' })
      .sort({ date: -1 })
      .toArray();

    res.json({ contributions: pending });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/contributions/:id/approve', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'creator') {
      return res.status(403).json({ message: 'Access denied. Creators only.' });
    }

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

    const updated = await contributions.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ contribution: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/contributions/:id/reject', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'creator') {
      return res.status(403).json({ message: 'Access denied. Creators only.' });
    }

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

    const updated = await contributions.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ contribution: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── Supporter routes ──────────────────────────────────────────

app.get('/api/supporter/stats', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'supporter') {
      return res.status(403).json({ message: 'Access denied. Supporters only.' });
    }

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

app.get('/api/supporter/approved-contributions', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'supporter') {
      return res.status(403).json({ message: 'Access denied. Supporters only.' });
    }

    const approved = await contributions
      .find({ supporterEmail: req.user.email, status: 'approved' })
      .sort({ date: -1 })
      .toArray();

    res.json({ contributions: approved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.post('/api/contributions', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'supporter') {
      return res.status(403).json({ message: 'Only supporters can contribute.' });
    }

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

    res.status(201).json({ contribution: saved });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/contributions', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'supporter') {
      return res.status(403).json({ message: 'Access denied. Supporters only.' });
    }

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

// ─── Admin routes ──────────────────────────────────────────────

app.get('/api/admin/stats', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

app.get('/api/admin/pending-campaigns', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

    const pending = await campaigns.find({ status: 'pending' }).sort({ createdAt: -1 }).toArray();
    res.json({ campaigns: pending });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/campaigns/:id/approve', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

    const updated = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ campaign: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/campaigns/:id/reject', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

    const updated = await campaigns.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ campaign: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/admin/pending-withdrawals', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

    const pending = await withdrawals.find({ status: 'pending' }).sort({ date: -1 }).toArray();
    res.json({ withdrawals: pending });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.patch('/api/withdrawals/:id/approve', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

    const updated = await withdrawals.findOne({ _id: new ObjectId(req.params.id) });
    res.json({ withdrawal: updated });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/users', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

app.patch('/api/users/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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
    res.json({ user: sanitizeUser(updated) });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.delete('/api/users/:id', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

app.delete('/api/campaigns/:id/admin', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

app.get('/api/reports', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

app.delete('/api/campaigns/:id/suspend', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

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

app.get('/', (req, res) => {
  res.send('This is home page of client server.');
});

app.use((req, res) => {
  res.status(404).json({ message: `Route ${req.originalUrl} not found` });
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
