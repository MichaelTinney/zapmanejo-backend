// ZapManejo Backend Dashboard API
// Node.js + Express + MongoDB backend for livestock management

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

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
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/zapmanejo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
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
    expiresAt: { type: Date, default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) } // 30 days trial
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
  totalArea: Number, // hectares
  pastures: [{
    name: String,
    area: Number,
    capacity: Number,
    currentOccupancy: { type: Number, default: 0 }
  }],
  subscription: {
    status: { type: String, enum: ['active', 'inactive', 'trial'], default: 'trial' },
    monthlyFee: { type: Number, default: 250 }, // R$ 250/month
    nextPayment: Date
  },
  whatsappConfig: {
    phoneNumber: String,
    accessToken: String,
    webhookVerifyToken: String,
    businessAccountId: String
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
  weight: { type: Number }, // kg
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
    action: String, // 'moved_cattle', 'vaccination', 'birth', 'feed_cost', etc.
    cattleAffected: [String], // array of cattle tags
    parsedData: mongoose.Schema.Types.Mixed
  },
  status: { type: String, enum: ['received', 'processing', 'processed', 'error'], default: 'received' },
  timestamp: { type: Date, default: Date.now }
});

// Activity Log Schema
const activitySchema = new mongoose.Schema({
  ranch: { type: mongoose.Schema.Types.ObjectId, ref: 'Ranch', required: true },
  user: { type: String }, // WhatsApp sender or dashboard user
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

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, ranchName, location } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create ranch first
    const ranch = new Ranch({
      name: ranchName,
      location,
      owner: null // Will be set after user creation
    });
    const savedRanch = await ranch.save();

    // Create user
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      ranch: savedRanch._id
    });
    const savedUser = await user.save();

    // Update ranch with owner
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
    
    // Get ranch info
    const ranch = await Ranch.findById(ranchId);
    
    // Get cattle statistics
    const totalCattle = await Cattle.countDocuments({ ranch: ranchId, status: 'active' });
    const cattleByPasture = await Cattle.aggregate([
      { $match: { ranch: mongoose.Types.ObjectId(ranchId), status: 'active' } },
      { $group: { _id: '$currentPasture.pastureName', count: { $sum: 1 } } }
    ]);
    
    // Get health alerts
    const healthAlerts = await Cattle.find({
      ranch: ranchId,
      status: 'active',
      'health.status': { $in: ['sick', 'treatment', 'quarantine'] }
    }).select('tag health.status').limit(10);

    // Get recent activities
    const recentActivities = await Activity.find({ ranch: ranchId })
      .sort({ timestamp: -1 })
      .limit(20);

    // Get breeding info
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

    // Log activity
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

    // Log activity
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

  if (mode && token === VERIFY_TOKEN) {
    console.log('Webhook verified');
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

app.post('/api/webhook', async (req, res) => {
  try {
    const body = req.body;

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

// WhatsApp message processing function
async function processWhatsAppMessage(message, phoneNumberId) {
  try {
    // Find ranch by phone number
    const ranch = await Ranch.findOne({ 'whatsappConfig.phoneNumber': phoneNumberId });
    if (!ranch) {
      console.error('Ranch not found for phone number:', phoneNumberId);
      return;
    }

    // Save message
    const savedMessage = new Message({
      ranch: ranch._id,
      phoneNumber: message.from,
      messageType: message.type,
      content: message.text?.body || message.caption || '',
      status: 'received'
    });
    await savedMessage.save();

    // Process message content using natural language processing
    const processedData = await processNaturalLanguage(message.text?.body || '', ranch._id);
    
    if (processedData) {
      savedMessage.processedData = processedData;
      savedMessage.status = 'processed';
      await savedMessage.save();

      // Execute the action
      await executeAction(processedData, ranch._id, message.from);
    }

  } catch (error) {
    console.error('Message processing error:', error);
  }
}

// Natural language processing function
async function processNaturalLanguage(messageText, ranchId) {
  const text = messageText.toLowerCase();
  
  // Movement detection
  if (text.includes('moved') || text.includes('transferi') || text.includes('mudei')) {
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

  // Vaccination detection
  if (text.includes('vacin') || text.includes('vaccine')) {
    const cattleNumbers = text.match(/\d+/g);
    const vaccineMatch = text.match(/(vacina|vaccine)\s*([a-z0-9]+)/i);
    
    return {
      action: 'vaccination',
      cattleCount: cattleNumbers?.[0] || '1',
      vaccine: vaccineMatch?.[2] || 'general'
    };
  }

  // Birth detection
  if (text.includes('birth') || text.includes('nasc') || text.includes('calf')) {
    const numbers = text.match(/\d+/g);
    return {
      action: 'birth',
      count: numbers?.[0] || '1'
    };
  }

  // Feed cost detection
  if (text.includes('feed') || text.includes('ração') || text.includes('cost')) {
    const numbers = text.match(/\d+/g);
    return {
      action: 'feed_cost',
      amount: numbers?.[0] || '0'
    };
  }

  return null;
}

// Action execution function
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

    // Execute specific actions based on type
    switch (processedData.action) {
      case 'moved_cattle':
        // Update cattle locations
        await updateCattleLocation(ranchId, processedData.cattleCount, processedData.pasture);
        break;
      
      case 'vaccination':
        // Record vaccination
        await recordVaccination(ranchId, processedData);
        break;
      
      case 'birth':
        // Record new births
        await recordBirth(ranchId, processedData.count);
        break;
      
      case 'feed_cost':
        // Record feeding costs
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
  // Simple implementation - in production, you'd want more sophisticated cattle selection
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
  // Record vaccination for cattle - simplified implementation
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
  // Create new cattle entries for births
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
  // In a real implementation, you'd have a separate expenses model
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
      { $match: { ranch: mongoose.Types.ObjectId(ranchId), status: 'active' } },
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
    version: '1.0.0'
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
  console.log(`ZapManejo Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;