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
    allowedHeaders: ['Content-Type', 'Authorization'],
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

async function run() {
  try {
    await client.connect();
    console.log('Successfully connected to MongoDB!');
    db = client.db('fundfrog');
    users = db.collection('users');
    campaigns = db.collection('campaigns');
    contributions = db.collection('contributions');
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
    const { top_funded, category, status, search } = req.query;
    const filter = {};

    if (category) filter.category = category;
    filter.status = status || 'approved';

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

app.get('/', (req, res) => {
  res.send('This is home page of client server.');
});

app.use((req, res) => {
  res.status(404).json({ message: `Route ${req.originalUrl} not found` });
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
