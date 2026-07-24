import express from 'express';
import { uaMiddleware } from '@exortek/ua/middleware/express';
import { isAICrawler } from '@exortek/ua/bots';

const app = express();

// Route-level (recommended — skip parsing on static assets)
app.get('/api/profile', uaMiddleware(), (req, res) => {
  res.json({
    browser: req.ua.browser.name,
    os: req.ua.os.name,
    device: req.ua.device.type || 'desktop',
    bot: req.ua.bot?.name || null,
  });
});

// Global with options
app.use(
  uaMiddleware({
    clientHints: true,
    sendAcceptCH: true,
    detectBots: true,
    property: 'ua',
    onUnknown(ua) {
      console.warn('Unrecognized UA:', ua.substring(0, 100));
    },
  }),
);

// Use parsed result in routes
app.get('/dashboard', (req, res) => {
  if (req.ua.device.type === 'mobile') {
    res.redirect('/m/dashboard');
    return;
  }

  if (req.ua.bot) {
    res.status(200).send('<html><body>Dashboard</body></html>');
    return;
  }

  res.render('dashboard', { browser: req.ua.browser.name });
});

// Block AI crawlers
app.use((req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  if (isAICrawler(ua)) {
    res.status(403).json({ error: 'AI crawling not permitted' });
    return;
  }
  next();
});

app.listen(3000);
