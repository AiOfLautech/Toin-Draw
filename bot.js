const { Telegraf } = require('telegraf');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
app.set('trust proxy', true);

const bot = new Telegraf(process.env.BOT_TOKEN);
const PORT = process.env.PORT || 3000;
const WEB_URL = process.env.RENDER_EXTERNAL_URL;
const LOGO_URL = 'https://files.catbox.moe/cbb551.jpg';

process.env.JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
process.env.PANEL_TOKEN = process.env.PANEL_TOKEN || crypto.randomBytes(16).toString('hex');

// Serve static files with cache
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Webhook setup
bot.telegram.setWebhook(`${WEB_URL}/webhook`);
app.use(bot.webhookCallback('/webhook'));

// Password generation
function generatePassword(length = 16, options = {}) {
  const chars = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  };
  let charSet = '';
  Object.keys(options).forEach((key) => {
    if (options[key]) charSet += chars[key];
  });
  return Array.from(crypto.randomBytes(length))
    .map((byte) => charSet[byte % charSet.length])
    .join('');
}

// JWT handling
function handleJWT(payload, secret = process.env.JWT_SECRET) {
  try {
    const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return {
      token,
      decoded: jwt.decode(token),
      verified: jwt.verify(token, secret),
    };
  } catch (error) {
    throw new Error(`JWT Error: ${error.message}`);
  }
}

// Website routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/panel', (req, res) => {
  if (req.query.token === process.env.PANEL_TOKEN) {
    res.sendFile(path.join(__dirname, 'public', 'panel.html'));
  } else {
    res.status(403).send('Invalid access token');
  }
});

// API endpoints
app.post('/generate-password', (req, res) => {
  try {
    const { length, options } = req.body;
    if (length < 8 || length > 64) throw new Error('Invalid length');
    res.json({ password: generatePassword(length, options) });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/generate-jwt', (req, res) => {
  try {
    const { payload, secret } = req.body;
    const result = handleJWT(payload, secret || undefined);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/decode-jwt', (req, res) => {
  try {
    const { token, secret } = req.body;
    const decoded = secret ? jwt.verify(token, secret) : jwt.decode(token);
    res.json({ decoded });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Telegram commands
bot.start(async (ctx) => {
  await ctx.sendChatAction('typing');
  try {
    await ctx.replyWithPhoto(LOGO_URL, {
      caption: '🔐 *SecureGenBot*\nAccess security tools:\n\n' +
               '/password - Generate password\n' +
               '/jwt - Generate JWT\n' +
               '/decode - Decode JWT\n' +
               '/web - Web interfaces\n' +
               '/help - Show commands',
      parse_mode: 'Markdown',
    });
  } catch {
    await ctx.replyWithMarkdown(
      '🔐 *SecureGenBot*\n\n' +
      'Access security tools:\n\n' +
      '/password - Generate password\n' +
      '/jwt - Generate JWT\n' +
      '/decode - Decode JWT\n' +
      '/web - Web interfaces\n' +
      '/help - Show commands'
    );
  }
});

bot.command('password', async (ctx) => {
  await ctx.sendChatAction('typing');
  const password = generatePassword(16, {
    upper: true,
    lower: true,
    numbers: true,
    symbols: true,
  });
  await ctx.reply(
    `🔑 Generated Password:\n\n<code>${password}</code>\n\n⚠️ Keep this secret!`,
    { parse_mode: 'HTML' }
  );
});

let waitingForJwt = false;
let waitingForDecode = false;

bot.command('jwt', async (ctx) => {
  waitingForJwt = true;
  waitingForDecode = false;
  await ctx.sendChatAction('typing');
  await ctx.replyWithMarkdown(
    '🔐 *JWT Generation*\n\n' +
    'Send claims in format:\n' +
    '`key1=value1, key2=value2`\n\n' +
    'Example: `user_id=123, role=admin`'
  );
});

bot.command('decode', async (ctx) => {
  waitingForDecode = true;
  waitingForJwt = false;
  await ctx.sendChatAction('typing');
  await ctx.replyWithMarkdown(
    '🔍 Send JWT token to decode:\n' +
    'Optionally include secret after space\n' +
    'Example: `eyJhbG... your_secret_here`'
  );
});

bot.command('web', async (ctx) => {
  await ctx.sendChatAction('typing');
  ctx.replyWithMarkdown(
    '🌐 *Web Interfaces*\n\n' +
    `[Password Generator](${WEB_URL}/?access=${uuidv4()})\n` +
    `[JWT Generator](${WEB_URL}/panel?token=${process.env.PANEL_TOKEN})`
  );
});

bot.command('help', async (ctx) => {
  await ctx.sendChatAction('typing');
  ctx.replyWithMarkdown(
    '*🤖 Command List*\n\n' +
    '/start - Show welcome message\n' +
    '/password - Generate password\n' +
    '/jwt - Generate JWT\n' +
    '/decode - Decode JWT\n' +
    '/web - Web interfaces\n' +
    '/help - Show this message'
  );
});

// Global text handler
bot.on('text', async (ctx) => {
  if (waitingForJwt && ctx.message.text.includes('=')) {
    try {
      await ctx.sendChatAction('typing');
      const claims = ctx.message.text
        .split(', ')
        .reduce((acc, pair) => {
          const [key, value] = pair.split('=');
          acc[key] = isNaN(value) ? value : Number(value);
          return acc;
        }, {});
      const { token, decoded } = handleJWT(claims);
      await ctx.replyWithMarkdown(
        `🔐 JWT Token:\n\n\`\`\`\n${token}\n\`\`\`\n\n` +
        `Decoded:\n\`\`\`json\n${JSON.stringify(decoded, null, 2)}\n\`\`\``
      );
      waitingForJwt = false;
    } catch (error) {
      await ctx.reply(`❌ Error: ${error.message}`);
    }
  } else if (waitingForDecode) {
    try {
      await ctx.sendChatAction('typing');
      const [token, secret] = ctx.message.text.split(' ');
      const decoded = secret ? jwt.verify(token, secret) : jwt.decode(token);
      await ctx.replyWithMarkdown(
        `🔍 Decoded JWT:\n\n\`\`\`json\n${JSON.stringify(decoded, null, 2)}\n\`\`\``
      );
      waitingForDecode = false;
    } catch (error) {
      await ctx.reply(`❌ Decode Error: ${error.message}`);
    }
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('⚠️ Server Error - Contact Support');
});

// Initialize
bot.telegram.getMe()
  .then((botInfo) => {
    app.listen(PORT, () => {
      console.log(`🚀 Server running at ${WEB_URL}`);
      console.log(`🔑 JWT_SECRET: ${process.env.JWT_SECRET}`);
      console.log(`🔐 PANEL_TOKEN: ${process.env.PANEL_TOKEN}`);
      console.log(`🤖 Bot @${botInfo.username} active`);
    });
  })
  .catch((error) => {
    console.error('Bot initialization failed:', error);
    process.exit(1);
  });

module.exports = app;
