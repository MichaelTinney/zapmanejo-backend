// ZapManejo Backend - Complete WhatsApp Livestock Management System
// Production-ready Node.js + Express + MongoDB backend with auto-demo ranch creation

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for DigitalOcean App Platform
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  trustProxy: true
});
app.use('/api/', limiter);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/zapmanejo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', function() {
  console.log('Connected to MongoDB successfully');
});

// User Schema
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

// Ranch Schema
const ranchSchema = new mongoose.Schema({
  name: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  location: {
    state: String,
    city: String,
    coordinates: { lat: Number, lng: Number }
  },
  totalArea: Number,
  pastures: [{
    name: String,
    area: Number,
    capacity: Number,
    currentOccupancy: { type: Number, default: 0 }
  }],
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

// Cattle Schema
const cattleSchema = new mongoose.Schema({
  tag: { type: String, required: true },
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  breed: String,
  gender: { type: String, enum: ['male', 'female'] },
  birthDate: Date,
  weight: { type: Number },
  mother: { type: mongoose.Schema.Types.ObjectId, ref: 'Cattle' },
  father: { type: mongoose.Schema.Types.ObjectId, ref: 'Cattle' },
  currentPasture: {
    pastureId: String,
    pastureName: String,
    movedDate: { type: Date, default: Date.now }
  },
  health: {
    vaccinations: [{
      type: String,
      date: Date,
      nextDue: Date,
      administeredBy: String
    }],
    treatments: [{
      condition: String,
      treatment: String,
      date: Date,
      cost: Number
    }],
    status: { type: String, enum: ['healthy', 'sick', 'treatment', 'quarantine'], default: 'healthy' }
  },
  breeding: {
    status: { type: String, enum: ['available', 'pregnant', 'nursing', 'retired'] },
    pregnancyDate: Date,
    expectedCalvingDate: Date,
    calvingHistory: [{
      date: Date,
      calfTag: String,
      complications: String
    }]
  },
  financial: {
    purchasePrice: Number,
    purchaseDate: Date,
    currentValue: Number
  },
  status: { type: String, enum: ['active', 'sold', 'deceased'], default: 'active' },
  notes: [{ 
    text: String, 
    date: { type: Date, default: Date.now },
    author: String 
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// WhatsApp Message Schema
const messageSchema = new mongoose.Schema({
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  phoneNumber: { type: String, required: true },
  senderName: String,
  messageType: { type: String, enum: ['text', 'image', 'audio', 'document'] },
  content: String,
  processedData: {
    action: String,
    cattleAffected: [String],
    parsedData: mongoose.Schema.Types.Mixed
  },
  status: { type: String, enum: ['received', 'processing', 'processed', 'error'], default: 'received' },
  timestamp: { type: Date, default: Date.now }
});

// Activity Log Schema
const activitySchema = new mongoose.Schema({
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  user: { type: String },
  action: { type: String, required: true },
  category: { type: String, enum: ['cattle', 'health', 'breeding', 'movement', 'financial', 'system'] },
  details: mongoose.Schema.Types.Mixed,
  cattleAffected: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Cattle' }],
  timestamp: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const Ranch = mongoose.model('Ranch', ranchSchema);
const Cattle = mongoose.model('Cattle', cattleSchema);
const Message = mongoose.model('Message', messageSchema);
const Activity = mongoose.model('Activity', activitySchema);

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// WhatsApp API helper function
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

// AUTO-CREATE DEMO RANCH FUNCTION
async function createDemoRanchIfNeeded() {
  try {
    const existingRanch = await Ranch.findOne();
    if (existingRanch) {
      return existingRanch;
    }

    console.log('Creating demo ranch and user...');

    // Create demo user
    const hashedPassword = await bcrypt.hash('demo123', 10);
    const demoUser = new User({
      name: "Demo Rancher",
      email: "demo@zapmanejo.com",
      phone: "15619720062",
      password: hashedPassword,
      role: "owner"
    });
    const savedUser = await demoUser.save();

    // Create demo ranch
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

    // Update user with ranch reference
    savedUser.ranch = savedRanch._id;
    await savedUser.save();

    // Create some demo cattle
    const demoCattle = [
      { tag: "DEMO001", breed: "Nelore", gender: "male", currentPasture: { pastureId: "norte", pastureName: "Pasto Norte" } },
      { tag: "DEMO002", breed: "Angus", gender: "female", currentPasture: { pastureId: "sul", pastureName: "Pasto Sul" } },
      { tag: "DEMO003", breed: "Brahman", gender: "male", currentPasture: { pastureId: "norte", pastureName: "Pasto Norte" } }
    ];

    for (const cattleData of demoCattle) {
      const cattle = new Cattle({
        ...cattleData,
        ranch: savedRanch._id,
        birthDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000), // Random date within last year
        weight: Math.floor(Math.random() * 200) + 300 // Random weight between 300-500kg
      });
      await cattle.save();
    }

    console.log('Demo ranch created successfully with sample cattle');
    return savedRanch;

  } catch (error) {
    console.error('Error creating demo ranch:', error);
    throw error;
  }
}

// ROOT ROUTE
app.get('/', (req, res) => {
  res.json({
    message: 'ZapManejo Backend API',
    version: '1.0.0',
    status: 'Running',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth/login',
      register: '/api/auth/register',
      dashboard: '/api/dashboard',
      cattle: '/api/cattle',
      webhook: '/api/webhook'
    }
  });
});

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, ranchName, location } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

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
      { userId: savedUser._id, ranchId: savedRanch._id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: savedUser._id,
        name: savedUser.name,
        email: savedUser.email,
        ranch: savedRanch.name
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).populate('ranch');
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, ranchId: user.ranch._id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '7d' }
    );

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
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DASHBOARD ROUTES
app.get('/api/dashboard', authenticateToken, async (req, res) => {
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

    const recentActivities = await Activity.find({ ranch: ranchId })
      .sort({ timestamp: -1 })
      .limit(20);

    const pregnantCattle = await Cattle.countDocuments({
      ranch: ranchId,
      status: 'active',
      'breeding.status': 'pregnant'
    });

    res.json({
      ranch: {
        name: ranch.name,
        totalArea: ranch.totalArea,
        pastureCount: ranch.pastures.length
      },
      statistics: {
        totalCattle,
        pregnantCattle,
        healthAlerts: healthAlerts.length,
        cattleByPasture
      },
      healthAlerts,
      recentActivities
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// CATTLE MANAGEMENT ROUTES
app.get('/api/cattle', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50, search, pasture, status } = req.query;
    const ranchId = req.user.ranchId;

    let query = { ranch: ranchId };
    
    if (search) {
      query.tag = new RegExp(search, 'i');
    }
    if (pasture) {
      query['currentPasture.pastureName'] = pasture;
    }
    if (status) {
      query.status = status;
    }

    const cattle = await Cattle.find(query)
      .sort({ tag: 1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Cattle.countDocuments(query);

    res.json({
      cattle,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });

  } catch (error) {
    console.error('Cattle fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cattle', authenticateToken, async (req, res) => {
  try {
    const cattleData = { ...req.body, ranch: req.user.ranchId };
    const cattle = new Cattle(cattleData);
    const savedCattle = await cattle.save();

    const activity = new Activity({
      ranch: req.user.ranchId,
      user: req.user.userId,
      action: 'cattle_added',
      category: 'cattle',
      details: { tag: savedCattle.tag },
      cattleAffected: [savedCattle._id]
    });
    await activity.save();

    res.status(201).json(savedCattle);
  } catch (error) {
    console.error('Cattle creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/cattle/:id', authenticateToken, async (req, res) => {
  try {
    const cattle = await Cattle.findOne({
      _id: req.params.id,
      ranch: req.user.ranchId
    }).populate('mother father', 'tag');

    if (!cattle) {
      return res.status(404).json({ error: 'Cattle not found' });
    }

    res.json(cattle);
  } catch (error) {
    console.error('Cattle fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/cattle/:id', authenticateToken, async (req, res) => {
  try {
    const cattle = await Cattle.findOneAndUpdate(
      { _id: req.params.id, ranch: req.user.ranchId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );

    if (!cattle) {
      return res.status(404).json({ error: 'Cattle not found' });
    }

    const activity = new Activity({
      ranch: req.user.ranchId,
      user: req.user.userId,
      action: 'cattle_updated',
      category: 'cattle',
      details: { tag: cattle.tag, changes: req.body },
      cattleAffected: [cattle._id]
    });
    await activity.save();

    res.json(cattle);
  } catch (error) {
    console.error('Cattle update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// WHATSAPP WEBHOOK ROUTES
app.get('/api/webhook', (req, res) => {
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
    res.sendStatus(403);
  }
});

app.post('/api/webhook', async (req, res) => {
  try {
    const body = req.body;
    console.log('Received webhook:', JSON.stringify(body, null, 2));

    if (body.object === 'whatsapp_business_account') {
      body.entry.forEach(async (entry) => {
        const changes = entry.changes;
        changes.forEach(async (change) => {
          if (change.field === 'messages') {
            const messages = change.value.messages;
            if (messages) {
              for (const message of messages) {
                await processWhatsAppMessage(message, change.value.metadata.phone_number_id);
              }
            }
          }
        });
      });
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// IMPROVED WhatsApp message processing function with auto-demo ranch creation
async function processWhatsAppMessage(message, phoneNumberId) {
  try {
    console.log('Processing message:', message);

    // Auto-create demo ranch if none exists
    let ranch = await createDemoRanchIfNeeded();

    const savedMessage = new Message({
      ranch: ranch._id,
      phoneNumber: message.from,
      messageType: message.type,
      content: message.text?.body || message.caption || '',
      status: 'received'
    });
    await savedMessage.save();

    const processedData = await processNaturalLanguage(message.text?.body || '', ranch._id);
    
    if (processedData) {
      savedMessage.processedData = processedData;
      savedMessage.status = 'processed';
      await savedMessage.save();

      await executeAction(processedData, ranch._id, message.from);
      
      const confirmationMessage = generateConfirmationMessage(processedData);
      const accessToken = process.env.WHATSAPP_ACCESS_TOKEN;
      
      if (accessToken) {
        await sendWhatsAppMessage(message.from, confirmationMessage, accessToken);
        console.log('Confirmation sent:', confirmationMessage);
      }
    } else {
      const helpMessage = "🐄 ZapManejo - Sistema de Gestão de Gado\n\nComandos disponíveis:\n• 'Movi 50 gado para pasto norte'\n• 'Vacinei 30 cabeças'\n• 'Nasceram 3 bezerros hoje'\n• 'Custo ração: R$2400'\n\nDigite sua ação em linguagem natural!";
      const accessToken = process.env.WHATSAPP_ACCESS_TOKEN;
      
      if (accessToken) {
        await sendWhatsAppMessage(message.from, helpMessage, accessToken);
      }
    }

  } catch (error) {
    console.error('Message processing error:', error);
  }
}

function generateConfirmationMessage(processedData) {
  switch (processedData.action) {
    case 'moved_cattle':
      return `✅ Registrado: ${processedData.cattleCount} cabeças movidas para ${processedData.pasture}\n🐄 ZapManejo - Gestão de Gado Inteligente`;
    case 'vaccination':
      return `💉 Registrado: Vacinação de ${processedData.cattleCount} cabeças com ${processedData.vaccine}\n🐄 ZapManejo - Gestão de Gado Inteligente`;
    case 'birth':
      return `🐄 Registrado: ${processedData.count} nascimento(s) hoje!\n🎉 ZapManejo - Gestão de Gado Inteligente`;
    case 'feed_cost':
      return `💰 Registrado: Custo de ração R$${processedData.amount}\n🐄 ZapManejo - Gestão de Gado Inteligente`;
    default:
      return `✅ Ação registrada no sistema ZapManejo\n🐄 Gestão de Gado Inteligente`;
  }
}

async function processNaturalLanguage(messageText, ranchId) {
  const text = messageText.toLowerCase();
  
  if (text.includes('moved') || text.includes('transferi') || text.includes('mudei') || text.includes('movi')) {
    const cattleNumbers = text.match(/\d+/g);
    const pastureMatch = text.match(/(pasto|pasture|field)\s*([a-z0-9]+)/i);
    
    if (cattleNumbers && pastureMatch) {
      return {
        action: 'moved_cattle',
        cattleCount: cattleNumbers[0],
        pasture: pastureMatch[2]
      };
    }
  }

  if (text.includes('vacin') || text.includes('vaccine')) {
    const cattleNumbers = text.match(/\d+/g);
    const vaccineMatch = text.match(/(vacina|vaccine)\s*([a-z0-9]+)/i);
    
    return {
      action: 'vaccination',
      cattleCount: cattleNumbers?.[0] || '1',
      vaccine: vaccineMatch?.[2] || 'general'
    };
  }

  if (text.includes('birth') || text.includes('nasc') || text.includes('calf') || text.includes('bezerr')) {
    const numbers = text.match(/\d+/g);
    return {
      action: 'birth',
      count: numbers?.[0] || '1'
    };
  }

  if (text.includes('feed') || text.includes('ração') || text.includes('cost') || text.includes('custo')) {
    const numbers = text.match(/\d+/g);
    return {
      action: 'feed_cost',
      amount: numbers?.[0] || '0'
    };
  }

  return null;
}

async function executeAction(processedData, ranchId, senderPhone) {
  try {
    const activity = new Activity({
      ranch: ranchId,
      user: senderPhone,
      action: processedData.action,
      category: getCategoryFromAction(processedData.action),
      details: processedData,
      timestamp: new Date()
    });

    await activity.save();

    switch (processedData.action) {
      case 'moved_cattle':
        await updateCattleLocation(ranchId, processedData.cattleCount, processedData.pasture);
        break;
      case 'vaccination':
        await recordVaccination(ranchId, processedData);
        break;
      case 'birth':
        await recordBirth(ranchId, processedData.count);
        break;
      case 'feed_cost':
        await recordFeedCost(ranchId, processedData.amount);
        break;
    }

  } catch (error) {
    console.error('Action execution error:', error);
  }
}

function getCategoryFromAction(action) {
  const categoryMap = {
    'moved_cattle': 'movement',
    'vaccination': 'health',
    'birth': 'breeding',
    'feed_cost': 'financial'
  };
  return categoryMap[action] || 'system';
}

async function updateCattleLocation(ranchId, cattleCount, pastureName) {
  const cattle = await Cattle.find({ ranch: ranchId, status: 'active' })
    .limit(parseInt(cattleCount));
  
  for (const animal of cattle) {
    animal.currentPasture = {
      pastureId: pastureName,
      pastureName: pastureName,
      movedDate: new Date()
    };
    await animal.save();
  }
}

async function recordVaccination(ranchId, data) {
  const cattle = await Cattle.find({ ranch: ranchId, status: 'active' })
    .limit(parseInt(data.cattleCount));
  
  for (const animal of cattle) {
    animal.health.vaccinations.push({
      type: data.vaccine,
      date: new Date(),
      administeredBy: 'WhatsApp Report'
    });
    await animal.save();
  }
}

async function recordBirth(ranchId, count) {
  for (let i = 0; i < parseInt(count); i++) {
    const newCattle = new Cattle({
      tag: `CALF_${Date.now()}_${i}`,
      ranch: ranchId,
      birthDate: new Date(),
      status: 'active'
    });
    await newCattle.save();
  }
}

async function recordFeedCost(ranchId, amount) {
  const activity = new Activity({
    ranch: ranchId,
    action: 'feed_expense_recorded',
    category: 'financial',
    details: { amount: parseFloat(amount), currency: 'BRL' },
    timestamp: new Date()
  });
  await activity.save();
}

// REPORTS AND ANALYTICS
app.get('/api/reports/cattle', authenticateToken, async (req, res) => {
  try {
    const ranchId = req.user.ranchId;
    
    const report = await Cattle.aggregate([
      { $match: { ranch: new mongoose.Types.ObjectId(ranchId), status: 'active' } },
      {
        $group: {
          _id: null,
          totalCattle: { $sum: 1 },
          avgWeight: { $avg: '$weight' },
          byGender: {
            $push: {
              gender: '$gender',
              count: 1
            }
          },
          byBreed: {
            $push: {
              breed: '$breed',
              count: 1
            }
          }
        }
      }
    ]);

    res.json(report[0] || {});
  } catch (error) {
    console.error('Report error:', error);
    res.status(500).json({ error: 'Report generation failed' });
  }
});

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    whatsapp: {
      configured: !!process.env.WHATSAPP_ACCESS_TOKEN,
      phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || 'Not configured'
    }
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 ZapManejo Backend running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📱 WhatsApp configured: ${!!process.env.WHATSAPP_ACCESS_TOKEN}`);
  console.log(`🗄️  MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
  console.log(`🐄 Auto-demo ranch creation: ENABLED`);
});

module.exports = app;
