const { Telegraf } = require('telegraf');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const progress = require('cli-progress');
require('dotenv').config();

const app = express();
const bot = new Telegraf(process.env.BOT_TOKEN);
const PORT = process.env.PORT || 3000;
const WEB_URL = process.env.RENDER_EXTERNAL_URL;

// Auto-generate secure secrets if not in .env
process.env.JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
process.env.PANEL_TOKEN = process.env.PANEL_TOKEN || crypto.randomBytes(16).toString('hex');

// Initialize progress bar
const progressBar = new progress.Bar({
    format: 'Progress |{bar}| {percentage}%',
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true
});

// Security Middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(limiter);
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Webhook Configuration
bot.telegram.setWebhook(`${WEB_URL}/webhook`);
app.use(bot.webhookCallback('/webhook'));
app.use(express.json());
app.use(express.static('public'));

// Password Generator with Progress
async function generatePassword(length = 16, options = {}, ctx) {
  const chars = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  let charSet = '';
  Object.keys(options).forEach(key => {
    if (options[key]) charSet += chars[key];
  });

  let progressMessage = await ctx.reply('🔒 Generating secure password...\n[░░░░░░░░░░] 0%');
  const startTime = Date.now();
  
  const updateInterval = setInterval(async () => {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(100, Math.floor((elapsed / 1500) * 100));
    const bars = '█'.repeat(Math.floor(progress / 10)) + '░'.repeat(10 - Math.floor(progress / 10));
    
    try {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        progressMessage.message_id,
        null,
        `🔒 Generating secure password...\n[${bars}] ${progress}%`
      );
    } catch (error) {
      clearInterval(updateInterval);
    }
  }, 500);

  const password = Array.from(crypto.randomBytes(length))
    .map(byte => charSet[byte % charSet.length])
    .join('');

  clearInterval(updateInterval);
  await ctx.telegram.deleteMessage(ctx.chat.id, progressMessage.message_id);
  return password;
}

// Fixed JWT Handler
function handleJWT(payload, secret = process.env.JWT_SECRET) {
  try {
    const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return {
      token,
      decoded: jwt.decode(token)
    };
  } catch (error) {
    throw new Error(`JWT Error: ${error.message}`);
  }
}

// Telegram Commands
bot.start((ctx) => {
  ctx.replyWithPhoto(
    { url: `${WEB_URL}/logo.png` },
    {
      caption: '🔐 *SecureGenBot*\nAccess security tools:\n\n' +
               '/generate - Password Generator\n' +
               '/panel - JWT Generator\n' +
               '/help - Show commands',
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [{ text: '🌐 Web Access', url: WEB_URL }]
        ]
      }
    }
  );
});

bot.command('generate', async (ctx) => {
  const token = uuidv4();
  ctx.reply(`🔑 Access Password Generator:\n${WEB_URL}/?token=${token}`);
});

bot.command('panel', (ctx) => {
  ctx.reply(`🔒 Access JWT Generator:\n${WEB_URL}/panel?token=${process.env.PANEL_TOKEN}`);
});

bot.command('help', (ctx) => {
  ctx.replyWithMarkdown(
    `*🤖 Command List*\n\n` +
    `/start - Show welcome message\n` +
    `/generate - Password generator web interface\n` +
    `/panel - JWT generator web interface\n` +
    `/help - Show this message`
  );
});

// Web Endpoints
app.post('/generate-password', async (req, res) => {
  try {
    const { length, options } = req.body;
    if (length < 8 || length > 64) throw new Error('Invalid length');
    const password = await generatePassword(length, options);
    res.json({ password });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/generate-jwt', (req, res) => {
  try {
    const result = handleJWT(req.body.payload, req.body.secret);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('⚠️ Server Error - Contact Support');
});

// Initialize bot and start server
bot.telegram.getMe().then((botInfo) => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running at ${WEB_URL}`);
    console.log(`🔑 JWT_SECRET: ${process.env.JWT_SECRET}`);
    console.log(`🔐 PANEL_TOKEN: ${process.env.PANEL_TOKEN}`);
    console.log(`🤖 Bot @${botInfo.username} active`);
  });
}).catch((error) => {
  console.error('Bot initialization failed:', error);
  process.exit(1);
});

module.exports = app;
