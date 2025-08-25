const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const nodemailer = require('nodemailer');
const i18n = require('i18n');
const mongoosePaginate = require('mongoose-paginate-v2');
const Redis = require('ioredis');
const Bull = require('bull');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'fallback-secret';
const goParserUrl = process.env.GO_PARSER_URL || 'https://parser-service:8081/parse-message';

// Trust proxy for DigitalOcean
app.set('trust proxy', 1);

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://oyster-app-zqs92.ondigitalocean.app',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

// Multilingual support
i18n.configure({
  locales: ['pt', 'es', 'en'],
  directory: __dirname + '/locales',
  defaultLocale: 'pt',
  queryParameter: 'lang',
  cookie: 'lang',
});
app.use(i18n.init);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  trustProxy: true
});
app.use('/api/', limiter);

// CSRF protection
const csrfProtection = csurf({ cookie: true });

// Audit logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: 'audit.log' })],
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/zapmanejo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB successfully'));

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['owner', 'manager', 'worker'], default: 'owner' },
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch' },
  whatsappConnected: { type: Boolean, default: false },
  subscription: {
    status: { type: String, enum: ['active', 'inactive', 'trial'], default: 'trial' },
    plan: { type: String, enum: ['basic', 'premium'], default: 'basic' },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
userSchema.plugin(mongoosePaginate);

const ranchSchema = new mongoose.Schema({
  name: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  location: { state: String, city: String, coordinates: { lat: Number, lng: Number } },
  totalArea: Number,
  pastures: [{ name: String, area: Number, capacity: Number, currentOccupancy: { type: Number, default: 0 } }],
  subscription: {
    status: { type: String, enum: ['active', 'inactive', 'trial'], default: 'trial' },
    monthlyFee: { type: Number, default: 250 },
    nextPayment: Date
  },
  whatsappConfig: {
    phoneNumber: String,
    accessToken: String,
    webhookVerifyToken: String,
    businessAccountId: String,
    phoneNumberId: String
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
ranchSchema.plugin(mongoosePaginate);

const cattleSchema = new mongoose.Schema({
  tag: { type: String, required: true },
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  breed: String,
  gender: { type: String, enum: ['male', 'female'] },
  birthDate: Date,
  weight: Number,
  mother: { type: mongoose.Schema.Types.ObjectId, ref: 'Cattle' },
  father: { type: mongoose.Schema.Types.ObjectId, ref: 'Cattle' },
  currentPasture: { pastureId: String, pastureName: String, movedDate: { type: Date, default: Date.now } },
  health: {
    vaccinations: [{ type: String, date: Date, nextDue: Date, administeredBy: String }],
    treatments: [{ condition: String, treatment: String, date: Date, cost: Number }],
    status: { type: String, enum: ['healthy', 'sick', 'treatment', 'quarantine'], default: 'healthy' }
  },
  breeding: {
    status: { type: String, enum: ['available', 'pregnant', 'nursing', 'retired'] },
    pregnancyDate: Date,
    expectedCalvingDate: Date,
    calvingHistory: [{ date: Date, calfTag: String, complications: String }]
  },
  financial: { purchasePrice: Number, purchaseDate: Date, currentValue: Number },
  status: { type: String, enum: ['active', 'sold', 'deceased'], default: 'active' },
  notes: [{ text: String, date: { type: Date, default: Date.now }, author: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
cattleSchema.plugin(mongoosePaginate);

const messageSchema = new mongoose.Schema({
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  phoneNumber: { type: String, required: true },
  senderName: String,
  messageType: { type: String, enum: ['text', 'image', 'audio', 'document'] },
  content: String,
  processedData: { action: String, cattleAffected: [String], parsedData: mongoose.Schema.Types.Mixed },
  status: { type: String, enum: ['received', 'processing', 'processed', 'error'], default: 'received' },
  timestamp: { type: Date, default: Date.now }
});
messageSchema.plugin(mongoosePaginate);

const activitySchema = new mongoose.Schema({
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  user: String,
  action: { type: String, required: true },
  category: { type: String, enum: ['cattle', 'health', 'breeding', 'movement', 'financial', 'system'] },
  details: mongoose.Schema.Types.Mixed,
  cattleAffected: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Cattle' }],
  timestamp: { type: Date, default: Date.now }
});
activitySchema.plugin(mongoosePaginate);

const milkProductionSchema = new mongoose.Schema({
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  tag: { type: String, required: true },
  amount: { type: Number, required: true },
  date: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});
milkProductionSchema.plugin(mongoosePaginate);

const User = mongoose.model('User', userSchema);
const Ranch = mongoose.model('Ranch', ranchSchema);
const Cattle = mongoose.model('Cattle', cattleSchema);
const Message = mongoose.model('Message', messageSchema);
const Activity = mongoose.model('Activity', activitySchema);
const MilkProduction = mongoose.model('MilkProduction', milkProductionSchema);

// Redis and Bull
const redis = new Redis(process.env.REDIS_URI || 'redis://localhost:6379');
const messageQueue = new Bull('message-processing', process.env.REDIS_URI || 'redis://localhost:6379');

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const lang = req.query.lang || 'pt';
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1] || req.query.token;
  if (!token) {
    return res.status(401).json({ message: i18n.__({ phrase: 'unauthorized', locale: lang }) });
  }
  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      return res.status(403).json({ message: i18n.__({ phrase: 'unauthorized', locale: lang }) });
    }
    req.user = user;
    next();
  });
};

const checkRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  next();
};

// Audit logging helper
const logAudit = async (userId, action, details) => {
  const audit = new Activity({
    ranch: details.ranchId || null,
    user: userId,
    action,
    category: 'system',
    details,
    timestamp: new Date()
  });
  await audit.save();
  logger.info({ userId, action, details });
};

// WhatsApp API helper
async function sendWhatsAppMessage(phoneNumber, message, accessToken) {
  try {
    const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    const response = await axios.post(
      `https://graph.facebook.com/v18.0/${phoneNumberId}/messages`,
      {
        messaging_product: "whatsapp",
        to: phoneNumber,
        type: "text",
        text: { body: message }
      },
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('WhatsApp send error:', error.response?.data || error.message);
    throw error;
  }
}

// Demo ranch creation
async function createDemoRanchIfNeeded() {
  try {
    const existingRanch = await Ranch.findOne();
    if (existingRanch) return existingRanch;
    console.log('Creating demo ranch and user...');
    const hashedPassword = await bcrypt.hash('demo123', 10);
    const demoUser = new User({
      name: "Demo Rancher",
      email: "demo@zapmanejo.com",
      phone: "15619720062",
      password: hashedPassword,
      role: "owner"
    });
    const savedUser = await demoUser.save();
    const demoRanch = new Ranch({
      name: "Fazenda Demo ZapManejo",
      owner: savedUser._id,
      location: { state: "MT", city: "Cuiabá" },
      pastures: [
        { name: "Pasto Norte", area: 100, capacity: 200, currentOccupancy: 50 },
        { name: "Pasto Sul", area: 80, capacity: 150, currentOccupancy: 30 },
        { name: "Pasto Leste", area: 120, capacity: 250, currentOccupancy: 80 }
      ],
      whatsappConfig: {
        phoneNumber: process.env.WHATSAPP_PHONE_NUMBER_ID,
        accessToken: process.env.WHATSAPP_ACCESS_TOKEN,
        webhookVerifyToken: process.env.WHATSAPP_VERIFY_TOKEN,
        businessAccountId: process.env.WHATSAPP_BUSINESS_ACCOUNT_ID,
        phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID
      }
    });
    const savedRanch = await demoRanch.save();
    savedUser.ranch = savedRanch._id;
    await savedUser.save();
    const demoCattle = [
      { tag: "DEMO001", breed: "Nelore", gender: "male", currentPasture: { pastureId: "norte", pastureName: "Pasto Norte" } },
      { tag: "DEMO002", breed: "Angus", gender: "female", currentPasture: { pastureId: "sul", pastureName: "Pasto Sul" } },
      { tag: "DEMO003", breed: "Brahman", gender: "male", currentPasture: { pastureId: "norte", pastureName: "Pasto Norte" } }
    ];
    for (const cattleData of demoCattle) {
      const cattle = new Cattle({
        ...cattleData,
        ranch: savedRanch._id,
        birthDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
        weight: Math.floor(Math.random() * 200) + 300
      });
      await cattle.save();
    }
    console.log('Demo ranch created successfully');
    return savedRanch;
  } catch (error) {
    console.error('Error creating demo ranch:', error);
    throw error;
  }
}

// Routes
app.get('/', (req, res) => {
  const lang = req.query.lang || 'pt';
  res.json({
    message: i18n.__({ phrase: 'success', locale: lang }),
    version: '1.0.0',
    status: 'Running',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth/login',
      register: '/api/auth/register',
      dashboard: '/api/dashboard',
      cattle: '/api/cattle',
      webhook: '/api/webhook',
      demo: '/api/demo',
      parseLogs: '/api/parse-logs',
      analytics: '/api/analytics',
      milkProduction: '/api/milk-production'
    }
  });
});

app.post('/api/auth/register', async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { name, email, phone, password, ranchName, location } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const ranch = new Ranch({
      name: ranchName,
      location,
      owner: null,
      whatsappConfig: {
        phoneNumber: process.env.WHATSAPP_PHONE_NUMBER_ID,
        accessToken: process.env.WHATSAPP_ACCESS_TOKEN,
        webhookVerifyToken: process.env.WHATSAPP_VERIFY_TOKEN,
        businessAccountId: process.env.WHATSAPP_BUSINESS_ACCOUNT_ID,
        phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID
      }
    });
    const savedRanch = await ranch.save();
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      ranch: savedRanch._id
    });
    const savedUser = await user.save();
    savedRanch.owner = savedUser._id;
    await savedRanch.save();
    const token = jwt.sign(
      { userId: savedUser._id, ranchId: savedRanch._id, role: savedUser.role },
      jwtSecret,
      { expiresIn: '7d' }
    );
    await logAudit(savedUser._id, 'user_registered', { email, ranchName });
    res.status(201).json({
      message: i18n.__({ phrase: 'success', locale: lang }),
      token,
      user: { id: savedUser._id, name, email, ranch: ranchName }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).populate('ranch');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: i18n.__({ phrase: 'unauthorized', locale: lang }) });
    }
    const token = jwt.sign(
      { userId: user._id, ranchId: user.ranch._id, role: user.role },
      jwtSecret,
      { expiresIn: '7d' }
    );
    await logAudit(user._id, 'user_login', { email });
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        ranch: user.ranch.name,
        subscription: user.subscription
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.post('/api/demo', async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { name, email, phone, farmName, state, cattleCount } = req.body;
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
    const mailOptions = {
      from: email,
      to: 'info@catalyticverticals.com',
      subject: 'ZapManejo Demo Request',
      text: `Name: ${name}\nEmail: ${email}\nPhone: ${phone}\nFarm: ${farmName}\nState: ${state}\nCattle Count: ${cattleCount}`
    };
    await transporter.sendMail(mailOptions);
    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(phone, 10);
      const ranch = new Ranch({
        name: farmName,
        location: { state },
        owner: null,
        subscription: { status: 'trial', expiresAt: new Date(Date.now() + 36 * 60 * 60 * 1000) }
      });
      const savedRanch = await ranch.save();
      const user = new User({
        name,
        email,
        phone,
        password: hashedPassword,
        ranch: savedRanch._id,
        subscription: { status: 'trial', expiresAt: new Date(Date.now() + 36 * 60 * 60 * 1000) }
      });
      const savedUser = await user.save();
      savedRanch.owner = savedUser._id;
      await savedRanch.save();
      await logAudit(savedUser._id, 'demo_registered', { email, farmName, state });
    }
    res.json({ message: i18n.__({ phrase: 'success', locale: lang }) });
  } catch (error) {
    console.error('Demo registration error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/dashboard', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const ranchId = req.user.ranchId;
    const ranch = await Ranch.findById(ranchId);
    const totalCattle = await Cattle.countDocuments({ ranch: ranchId, status: 'active' });
    const cattleByPasture = await Cattle.aggregate([
      { $match: { ranch: new mongoose.Types.ObjectId(ranchId), status: 'active' } },
      { $group: { _id: '$currentPasture.pastureName', count: { $sum: 1 } } }
    ]);
    const healthAlerts = await Cattle.find({
      ranch: ranchId,
      status: 'active',
      'health.status': { $in: ['sick', 'treatment', 'quarantine'] }
    }).select('tag health.status').limit(10);
    const recentActivities = await Activity.find({ ranch: ranchId }).sort({ timestamp: -1 }).limit(20);
    const pregnantCattle = await Cattle.countDocuments({
      ranch: ranchId,
      status: 'active',
      'breeding.status': 'pregnant'
    });
    const cacheKey = `dashboard:${ranchId}`;
    await redis.set(cacheKey, JSON.stringify({
      ranch: { name: ranch.name, totalArea: ranch.totalArea, pastureCount: ranch.pastures.length },
      statistics: { totalCattle, pregnantCattle, healthAlerts: healthAlerts.length, cattleByPasture },
      healthAlerts,
      recentActivities
    }), 'EX', 300);
    await logAudit(req.user.userId, 'view_dashboard', { ranchId });
    res.json({
      ranch: { name: ranch.name, totalArea: ranch.totalArea, pastureCount: ranch.pastures.length },
      statistics: { totalCattle, pregnantCattle, healthAlerts: healthAlerts.length, cattleByPasture },
      healthAlerts,
      recentActivities
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/cattle', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { page = 1, limit = 50, search, pasture, status } = req.query;
    let query = { ranch: req.user.ranchId };
    if (search) query.tag = new RegExp(search, 'i');
    if (pasture) query['currentPasture.pastureName'] = pasture;
    if (status) query.status = status;
    const cattle = await Cattle.find(query)
      .sort({ tag: 1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    const total = await Cattle.countDocuments(query);
    await logAudit(req.user.userId, 'view_cattle', { page, limit, ranchId: req.user.ranchId });
    res.json({
      cattle,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Cattle fetch error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.post('/api/cattle', authenticateToken, checkRole(['owner', 'manager']), async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const cattleData = { ...req.body, ranch: req.user.ranchId };
    const cattle = new Cattle(cattleData);
    const savedCattle = await cattle.save();
    await logAudit(req.user.userId, 'cattle_added', { tag: savedCattle.tag, ranchId: req.user.ranchId });
    res.status(201).json(savedCattle);
  } catch (error) {
    console.error('Cattle creation error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/cattle/:id', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const cattle = await Cattle.findOne({
      _id: req.params.id,
      ranch: req.user.ranchId
    }).populate('mother father', 'tag');
    if (!cattle) {
      return res.status(404).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
    }
    await logAudit(req.user.userId, 'view_cattle_details', { cattleId: req.params.id });
    res.json(cattle);
  } catch (error) {
    console.error('Cattle fetch error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.put('/api/cattle/:id', authenticateToken, checkRole(['owner', 'manager']), async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const cattle = await Cattle.findOneAndUpdate(
      { _id: req.params.id, ranch: req.user.ranchId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );
    if (!cattle) {
      return res.status(404).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
    }
    await logAudit(req.user.userId, 'cattle_updated', { tag: cattle.tag, changes: req.body });
    res.json(cattle);
  } catch (error) {
    console.error('Cattle update error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/parse-logs', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { page = 1, limit = 10, ranchId } = req.query;
    const cacheKey = `parse-logs:${ranchId || req.user.ranchId}:${page}:${limit}`;
    const cached = await redis.get(cacheKey);
    if (cached) {
      return res.json(JSON.parse(cached));
    }
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { timestamp: -1 }
    };
    const query = ranchId ? { ranch: ranchId } : { ranch: req.user.ranchId };
    const result = await Message.paginate(query, options);
    await redis.set(cacheKey, JSON.stringify(result), 'EX', 300);
    await logAudit(req.user.userId, 'view_parse_logs', { page, limit, ranchId: req.user.ranchId });
    res.json(result);
  } catch (error) {
    console.error('Parse logs fetch error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/analytics', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const ranchId = req.user.ranchId;
    const trends = await Cattle.aggregate([
      { $match: { ranch: new mongoose.Types.ObjectId(ranchId), status: 'active' } },
      {
        $group: {
          _id: { $month: '$createdAt' },
          count: { $sum: 1 },
          avgWeight: { $avg: '$weight' }
        }
      },
      { $sort: { '_id': 1 } }
    ]);
    await logAudit(req.user.userId, 'view_analytics', { ranchId });
    res.json({ trends });
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/milk-production', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { page = 1, limit = 10 } = req.query;
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { date: -1 }
    };
    const result = await MilkProduction.paginate({ ranch: req.user.ranchId }, options);
    await logAudit(req.user.userId, 'view_milk_logs', { page, limit, ranchId: req.user.ranchId });
    res.json(result.docs);
  } catch (error) {
    console.error('Milk production fetch error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.post('/api/milk-production', authenticateToken, checkRole(['owner', 'manager']), async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const { tag, amount, date } = req.body;
    const milkRecord = new MilkProduction({
      ranch: req.user.ranchId,
      tag,
      amount,
      date: new Date(date)
    });
    const savedRecord = await milkRecord.save();
    await logAudit(req.user.userId, 'milk_production_added', { tag, amount, ranchId: req.user.ranchId });
    res.status(201).json(savedRecord);
  } catch (error) {
    console.error('Milk production creation error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/webhook', (req, res) => {
  const lang = req.query.lang || 'pt';
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'zapmanejo_verify';
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  console.log('Webhook verification attempt:', { mode, token, challenge });
  if (mode && token === VERIFY_TOKEN) {
    console.log('Webhook verified successfully');
    res.status(200).send(challenge);
  } else {
    console.log('Webhook verification failed');
    res.status(403).json({ error: i18n.__({ phrase: 'unauthorized', locale: lang }) });
  }
});

app.post('/api/webhook', async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const body = req.body;
    console.log('Received webhook:', JSON.stringify(body, null, 2));
    if (body.object === 'whatsapp_business_account') {
      body.entry.forEach(entry => {
        entry.changes.forEach(change => {
          if (change.field === 'messages') {
            const messages = change.value.messages;
            if (messages) {
              messages.forEach(message => {
                messageQueue.add({
                  message: message.text?.body || '',
                  phoneNumber: message.from,
                  senderName: change.value.contacts?.[0]?.profile?.name || '',
                  ranchId: 'default_ranch_id',
                  lang
                });
              });
            }
          }
        });
      });
    }
    res.status(200).send('OK');
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

messageQueue.process(async (job) => {
  const { message, phoneNumber, senderName, ranchId, lang } = job.data;
  const serviceToken = jwt.sign(
    { user_id: 'service', email: 'service@zapmanejo.com', phone_number: phoneNumber },
    jwtSecret,
    { expiresIn: '1h' }
  );
  try {
    const response = await axios.post(goParserUrl, {
      message,
      ranchId,
      phoneNumber,
      senderName
    }, {
      headers: { Authorization: `Bearer ${serviceToken}` },
      params: { lang }
    });
    const parsedData = response.data;
    const savedMessage = new Message({
      ranch: ranchId,
      phoneNumber,
      senderName,
      messageType: 'text',
      content: message,
      processedData: parsedData,
      status: 'processed'
    });
    await savedMessage.save();
    await logAudit(phoneNumber, 'message_processed', { ranchId, parsedData });
    if (parsedData.action === 'weather') {
      const apiKey = process.env.OPENWEATHER_API_KEY;
      if (apiKey && parsedData.address) {
        const weatherResponse = await axios.get(`https://api.openweathermap.org/data/2.5/weather?q=${parsedData.address}&appid=${apiKey}&units=metric`);
        const weatherData = weatherResponse.data;
        const weatherMessage = `🌤️ Clima em ${parsedData.address}: ${weatherData.weather[0].description}, ${weatherData.main.temp}°C`;
        await sendWhatsAppMessage(phoneNumber, weatherMessage, process.env.WHATSAPP_ACCESS_TOKEN);
      }
    }
  } catch (error) {
    console.error('Message processing error:', error);
  }
});

app.get('/api/reports/cattle', authenticateToken, async (req, res) => {
  const lang = req.query.lang || 'pt';
  try {
    const ranchId = req.user.ranchId;
    const report = await Cattle.aggregate([
      { $match: { ranch: new mongoose.Types.ObjectId(ranchId), status: 'active' } },
      {
        $group: {
          _id: null,
          totalCattle: { $sum: 1 },
          avgWeight: { $avg: '$weight' },
          byGender: { $push: { gender: '$gender', count: 1 } },
          byBreed: { $push: { breed: '$breed', count: 1 } }
        }
      }
    ]);
    await logAudit(req.user.userId, 'view_report', { ranchId, reportType: 'cattle' });
    res.json(report[0] || {});
  } catch (error) {
    console.error('Report error:', error);
    res.status(500).json({ error: i18n.__({ phrase: 'error', locale: lang }) });
  }
});

app.get('/api/health', (req, res) => {
  const lang = req.query.lang || 'pt';
  res.json({
    status: i18n.__({ phrase: 'success', locale: lang }),
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    whatsapp: {
      configured: !!process.env.WHATSAPP_ACCESS_TOKEN,
      phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || 'Not configured'
    }
  });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: i18n.__({ phrase: 'error', locale: 'pt' }) });
});

app.use('*', (req, res) => {
  res.status(404).json({ error: i18n.__({ phrase: 'error', locale: 'pt' }) });
});

app.listen(PORT, () => {
  console.log(`🚀 ZapManejo Backend running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📱 WhatsApp configured: ${!!process.env.WHATSAPP_ACCESS_TOKEN}`);
  console.log(`🗄️ MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
  createDemoRanchIfNeeded();
});
