const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '.env' });

const app = express();
app.use(express.json());
app.use(express.static('public'));

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name } = req.body;
  try {
    // First user becomes admin
    const count = await db.query('SELECT COUNT(*) FROM users');
    const role = parseInt(count.rows[0].count) === 0 ? 'admin' : 'member';
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await db.query(
      'INSERT INTO users (email, password_hash, name, role) VALUES ($1,$2,$3,$4) RETURNING id, email, name, role',
      [email, hash, name, role]
    );
    const token = jwt.sign({ id: rows[0].id, email: rows[0].email, role: rows[0].role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: rows[0] });
  } catch(e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!rows[0]) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: rows[0].id, email: rows[0].email, role: rows[0].role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: rows[0].id, email: rows[0].email, name: rows[0].name, role: rows[0].role } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const { rows } = await db.query('SELECT id, email, name, role FROM users WHERE id = $1', [req.user.id]);
  res.json(rows[0]);
});

// ─────────────────────────────────────────
// PIXEL SETTINGS
// ─────────────────────────────────────────
app.get('/api/pixels', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? req.query.user_id || req.user.id : req.user.id;
    const { rows } = await db.query(
      'SELECT * FROM pixel_settings WHERE user_id = $1',
      [userId]
    );
    res.json(rows);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/pixels', authMiddleware, async (req, res) => {
  const { platform, pixel_id, access_token, enabled } = req.body;
  try {
    const { rows } = await db.query(`
      INSERT INTO pixel_settings (user_id, platform, pixel_id, access_token, enabled)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (user_id, platform) DO UPDATE
      SET pixel_id=$3, access_token=$4, enabled=$5, updated_at=NOW()
      RETURNING *`,
      [req.user.id, platform, pixel_id, access_token, enabled !== false]
    );
    res.json(rows[0]);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────
// STATS API
// ─────────────────────────────────────────
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const isAdmin = req.user.role === 'admin';
    const userId = req.user.id;

    const userFilter = isAdmin ? '' : 'AND o.user_id = $2';
    const userFilterClicks = isAdmin ? '' : 'AND user_id = $2';
    const params = isAdmin ? [today] : [today, userId];
    const paramsY = isAdmin ? [yesterday] : [yesterday, userId];

    const [todayStats, totalStats, clickStats, platformStats, yesterdayStats] = await Promise.all([
      db.query(`SELECT COUNT(*) as orders, COALESCE(SUM(payout),0) as revenue FROM orders o WHERE DATE(received_at)=$1 ${userFilter}`, params),
      db.query(`SELECT COUNT(*) as orders, COALESCE(SUM(payout),0) as revenue FROM orders o WHERE 1=1 ${userFilter.replace('AND o.','AND ')}`, isAdmin ? [] : [userId]),
      db.query(`SELECT COUNT(*) as clicks FROM clicks WHERE 1=1 ${userFilterClicks}`, isAdmin ? [] : [userId]),
      db.query(`SELECT c.traffic_source as source, COALESCE(SUM(o.payout),0) as revenue, COUNT(o.id) as orders FROM orders o LEFT JOIN clicks c ON o.click_id=c.click_id WHERE DATE(o.received_at)=$1 ${userFilter} GROUP BY c.traffic_source`, params),
      db.query(`SELECT COUNT(*) as orders, COALESCE(SUM(payout),0) as revenue FROM orders o WHERE DATE(received_at)=$1 ${userFilter}`, paramsY)
    ]);

    const todayRev = parseFloat(todayStats.rows[0].revenue);
    const todayOrd = parseInt(todayStats.rows[0].orders);
    const totalRev = parseFloat(totalStats.rows[0].revenue);
    const totalOrd = parseInt(totalStats.rows[0].orders);
    const totalClk = parseInt(clickStats.rows[0].clicks);
    const yRev = parseFloat(yesterdayStats.rows[0].revenue);
    const yOrd = parseInt(yesterdayStats.rows[0].orders);

    res.json({
      revenue_today: todayRev,
      orders_today: todayOrd,
      revenue_total: totalRev,
      total_orders: totalOrd,
      total_clicks: totalClk,
      conversion_rate: totalClk > 0 ? (totalOrd / totalClk * 100) : 0,
      revenue_change: yRev > 0 ? ((todayRev - yRev) / yRev * 100) : 0,
      orders_change: todayOrd - yOrd,
      by_platform: platformStats.rows
    });
  } catch(e) {
    console.error('Stats error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────
// ORDERS API
// ─────────────────────────────────────────
app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const { period, limit = 50, offset = 0 } = req.query;
    const isAdmin = req.user.role === 'admin';
    const userId = req.user.id;

    let dateFilter = '';
    if (period === 'today') dateFilter = "AND DATE(o.received_at) = CURRENT_DATE";
    else if (period === 'yesterday') dateFilter = "AND DATE(o.received_at) = CURRENT_DATE - 1";
    else if (period === '7days') dateFilter = "AND o.received_at >= NOW() - INTERVAL '7 days'";
    else if (period === '30days') dateFilter = "AND o.received_at >= NOW() - INTERVAL '30 days'";

    const userFilter = isAdmin ? '' : 'AND o.user_id = $3';
    const params = isAdmin ? [limit, offset] : [limit, offset, userId];

    const { rows } = await db.query(`
      SELECT
        o.id, o.transaction_id, o.payout, o.network, o.received_at,
        o.offer_name, o.landing_page_url, o.ad_creative, o.country, o.device_type,
        o.pixel_fired_fb, o.pixel_fired_tt,
        c.traffic_source, c.campaign_id, c.ad_id
      FROM orders o
      LEFT JOIN clicks c ON o.click_id = c.click_id
      WHERE 1=1 ${dateFilter} ${userFilter}
      ORDER BY o.received_at DESC
      LIMIT $1 OFFSET $2
    `, params);

    res.json(rows);
  } catch(e) {
    console.error('Orders error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────
// ANALYTICS API
// ─────────────────────────────────────────
app.get('/api/analytics', authMiddleware, async (req, res) => {
  try {
    const { period = '30days' } = req.query;
    const isAdmin = req.user.role === 'admin';
    const userId = req.user.id;

    let dateFilter = "AND o.received_at >= NOW() - INTERVAL '30 days'";
    if (period === 'today') dateFilter = "AND DATE(o.received_at) = CURRENT_DATE";
    else if (period === 'yesterday') dateFilter = "AND DATE(o.received_at) = CURRENT_DATE - 1";
    else if (period === '7days') dateFilter = "AND o.received_at >= NOW() - INTERVAL '7 days'";

    const userFilter = isAdmin ? '' : 'AND o.user_id = $1';
    const params = isAdmin ? [] : [userId];

    const { rows } = await db.query(`
      SELECT
        o.offer_name,
        o.landing_page_url,
        o.ad_creative,
        o.country,
        o.device_type,
        c.traffic_source as platform,
        COUNT(o.id) as sales,
        COALESCE(SUM(o.payout), 0) as revenue,
        AVG(o.payout) as avg_payout
      FROM orders o
      LEFT JOIN clicks c ON o.click_id = c.click_id
      WHERE 1=1 ${dateFilter} ${userFilter}
      GROUP BY o.offer_name, o.landing_page_url, o.ad_creative, o.country, o.device_type, c.traffic_source
      ORDER BY revenue DESC
    `, params);

    res.json(rows);
  } catch(e) {
    console.error('Analytics error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────
// CLICK TRACKING
// ─────────────────────────────────────────
app.get('/track/click', async (req, res) => {
  const { click_id, source, campaign, adset, ad, fbclid, ttclid, gclid, user_id } = req.query;
  try {
    await db.query(`
      INSERT INTO clicks (click_id, traffic_source, campaign_id, adset_id, ad_id, fbclid, ttclid, gclid, ip, user_agent, user_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (click_id) DO NOTHING`,
      [click_id, source, campaign, adset, ad, fbclid, ttclid, gclid, req.ip, req.headers['user-agent'], user_id || null]
    );
    res.send('OK');
  } catch(e) {
    console.error('Click error:', e.message);
    res.status(500).send('Error');
  }
});

// ─────────────────────────────────────────
// POSTBACK
// ─────────────────────────────────────────
app.get('/postback', async (req, res) => {
  const { click_id, payout, transaction_id, offer_id, network, offer_name, lp_url, creative, country, device } = req.query;
  try {
    const clickData = await db.query('SELECT * FROM clicks WHERE click_id = $1', [click_id]);
    const click = clickData.rows[0];

    await db.query(`
      INSERT INTO orders (click_id, network, offer_id, payout, transaction_id, offer_name, landing_page_url, ad_creative, country, device_type, user_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (transaction_id) DO NOTHING`,
      [click_id, network || 'unknown', offer_id, parseFloat(payout) || 0, transaction_id,
       offer_name || null, lp_url || null, creative || click?.ad_id || null,
       country || null, device || null, click?.user_id || null]
    );

    await Promise.all([
      firePixels(click_id, payout, transaction_id, click),
      notifyPhone({ payout, network, transaction_id }, click)
    ]);

    res.send('OK');
  } catch(e) {
    console.error('Postback error:', e.message);
    res.status(500).send('Error');
  }
});

// ─────────────────────────────────────────
// FIRE PIXELS
// ─────────────────────────────────────────
async function firePixels(click_id, payout, transaction_id, click = {}) {
  // Facebook CAPI
  try {
    if (process.env.FB_PIXEL_ID && process.env.FB_ACCESS_TOKEN) {
      await fetch(
        `https://graph.facebook.com/v18.0/${process.env.FB_PIXEL_ID}/events?access_token=${process.env.FB_ACCESS_TOKEN}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            data: [{
              event_name: 'Purchase',
              event_time: Math.floor(Date.now() / 1000),
              event_id: transaction_id,
              action_source: 'website',
              custom_data: { value: parseFloat(payout), currency: 'USD' },
              user_data: {
                fbc: click?.fbclid ? `fb.1.${Date.now()}.${click.fbclid}` : undefined,
                client_ip_address: click?.ip,
                client_user_agent: click?.user_agent
              }
            }]
          })
        }
      );
      await db.query('UPDATE orders SET pixel_fired_fb=TRUE WHERE transaction_id=$1', [transaction_id]);
    }
  } catch(e) { console.error('FB CAPI error:', e.message); }

  // TikTok Events API
  try {
    if (process.env.TT_PIXEL_ID && process.env.TT_ACCESS_TOKEN) {
      await fetch('https://business-api.tiktok.com/open_api/v1.3/event/track/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Access-Token': process.env.TT_ACCESS_TOKEN },
        body: JSON.stringify({
          pixel_code: process.env.TT_PIXEL_ID,
          event: 'CompletePayment',
          event_id: transaction_id,
          timestamp: new Date().toISOString(),
          properties: { value: parseFloat(payout), currency: 'USD' },
          context: { ip: click?.ip, user_agent: click?.user_agent, ttclid: click?.ttclid }
        })
      });
      await db.query('UPDATE orders SET pixel_fired_tt=TRUE WHERE transaction_id=$1', [transaction_id]);
    }
  } catch(e) { console.error('TikTok error:', e.message); }
}

// ─────────────────────────────────────────
// NOTIFY PHONE
// ─────────────────────────────────────────
async function notifyPhone(order, click) {
  try {
    if (!process.env.PUSHOVER_API_TOKEN || !process.env.PUSHOVER_USER_KEY) return;
    const source   = click?.traffic_source || 'Unknown';
    const campaign = click?.campaign_id    || '–';
    const payout   = parseFloat(order.payout || 0).toFixed(2);
    await fetch('https://api.pushover.net/1/messages.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token:    process.env.PUSHOVER_API_TOKEN,
        user:     process.env.PUSHOVER_USER_KEY,
        title:    `🔥 Sale — +$${payout}`,
        message:  `Source: ${source}\nCampaign: ${campaign}\nNetwork: ${order.network}`,
        sound:    'cashregister',
        priority: 1
      })
    });
  } catch(e) { console.error('Pushover error:', e.message); }
}

// ─────────────────────────────────────────
// START
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Tracker running on port ${PORT}`));