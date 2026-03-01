const express = require('express');
const { Pool } = require('pg');
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

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const count = await db.query('SELECT COUNT(*) FROM users');
    const role = parseInt(count.rows[0].count) === 0 ? 'admin' : 'member';
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await db.query(
      'INSERT INTO users (email,password_hash,name,role) VALUES ($1,$2,$3,$4) RETURNING id,email,name,role',
      [email, hash, name, role]
    );
    const token = jwt.sign({ id: rows[0].id, email: rows[0].email, role: rows[0].role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: rows[0] });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows[0]) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: rows[0].id, email: rows[0].email, role: rows[0].role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: rows[0].id, email: rows[0].email, name: rows[0].name, role: rows[0].role } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { rows } = await db.query('SELECT id,email,name,role FROM users WHERE id=$1', [req.user.id]);
  res.json(rows[0]);
});

// ─────────────────────────────────────────
// ADMIN — TEAM
// ─────────────────────────────────────────
app.get('/api/team', auth, adminOnly, async (req, res) => {
  const { rows } = await db.query('SELECT id,email,name,role,created_at FROM users ORDER BY created_at');
  res.json(rows);
});

app.get('/api/team/:userId/stats', auth, adminOnly, async (req, res) => {
  try {
    const uid = req.params.userId;
    const { period = '30days' } = req.query;

    let df = "AND received_at >= NOW() - INTERVAL '30 days'";
    if (period === 'today') df = "AND DATE(received_at)=CURRENT_DATE";
    if (period === 'yesterday') df = "AND DATE(received_at)=CURRENT_DATE-1";
    if (period === '7days') df = "AND received_at >= NOW() - INTERVAL '7 days'";
    if (period === '6months') df = "AND received_at >= NOW() - INTERVAL '6 months'";
    if (period === 'year') df = "AND received_at >= NOW() - INTERVAL '1 year'";

    const [summary, byPlatform, byOffer, daily] = await Promise.all([
      db.query(`SELECT COUNT(*) as orders, COALESCE(SUM(payout),0) as revenue, COALESCE(AVG(payout),0) as aov FROM orders WHERE user_id=$1 ${df}`, [uid]),
      db.query(`SELECT c.traffic_source as platform, COUNT(o.id) as orders, COALESCE(SUM(o.payout),0) as revenue FROM orders o LEFT JOIN clicks c ON o.click_id=c.click_id WHERE o.user_id=$1 ${df} GROUP BY c.traffic_source ORDER BY revenue DESC`, [uid]),
      db.query(`SELECT COALESCE(offer_name,'Unknown') as offer, COUNT(*) as orders, COALESCE(SUM(payout),0) as revenue FROM orders WHERE user_id=$1 ${df} GROUP BY offer_name ORDER BY revenue DESC LIMIT 10`, [uid]),
      db.query(`SELECT DATE(received_at) as date, COUNT(*) as orders, COALESCE(SUM(payout),0) as revenue FROM orders WHERE user_id=$1 ${df} GROUP BY DATE(received_at) ORDER BY date`, [uid])
    ]);

    const totalClicks = await db.query(`SELECT COUNT(*) as clicks FROM clicks WHERE user_id=$1`, [uid]);
    const totalOrders = parseInt(summary.rows[0].orders);
    const totalClicksCount = parseInt(totalClicks.rows[0].clicks);

    res.json({
      summary: {
        ...summary.rows[0],
        total_clicks: totalClicksCount,
        cvr: totalClicksCount > 0 ? (totalOrders / totalClicksCount * 100).toFixed(2) : 0
      },
      by_platform: byPlatform.rows,
      by_offer: byOffer.rows,
      daily: daily.rows
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// PIXELS (multiple per platform)
// ─────────────────────────────────────────
app.get('/api/pixels', auth, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT * FROM pixel_settings WHERE user_id=$1 ORDER BY platform, pixel_name',
      [req.user.id]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pixels', auth, async (req, res) => {
  const { platform, pixel_name, pixel_id, access_token, snap_pixel_id, enabled } = req.body;
  try {
    const { rows } = await db.query(`
      INSERT INTO pixel_settings (user_id, platform, pixel_name, pixel_id, access_token, snap_pixel_id, enabled)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT (user_id, platform, pixel_name) DO UPDATE
      SET pixel_id=$4, access_token=$5, snap_pixel_id=$6, enabled=$7, updated_at=NOW()
      RETURNING *`,
      [req.user.id, platform, pixel_name || 'Default', pixel_id, access_token, snap_pixel_id, enabled !== false]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/pixels/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM pixel_settings WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Offer pixel assignments
app.get('/api/pixels/assignments', auth, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT opa.*, ps.pixel_name, ps.platform FROM offer_pixel_assignments opa JOIN pixel_settings ps ON opa.pixel_setting_id=ps.id WHERE opa.user_id=$1',
      [req.user.id]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pixels/assignments', auth, async (req, res) => {
  const { offer_name, pixel_setting_id } = req.body;
  try {
    const { rows } = await db.query(`
      INSERT INTO offer_pixel_assignments (user_id, offer_name, pixel_setting_id)
      VALUES ($1,$2,$3)
      ON CONFLICT DO NOTHING RETURNING *`,
      [req.user.id, offer_name, pixel_setting_id]
    );
    res.json(rows[0] || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/pixels/assignments/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM offer_pixel_assignments WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// NOTIFICATIONS
// ─────────────────────────────────────────
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM notification_settings WHERE user_id=$1', [req.user.id]);
    res.json(rows[0] || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications', auth, async (req, res) => {
  const { pushover_user_key, pushover_api_token, enabled } = req.body;
  try {
    const { rows } = await db.query(`
      INSERT INTO notification_settings (user_id,pushover_user_key,pushover_api_token,enabled)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (user_id) DO UPDATE SET pushover_user_key=$2,pushover_api_token=$3,enabled=$4,updated_at=NOW()
      RETURNING *`,
      [req.user.id, pushover_user_key, pushover_api_token, enabled !== false]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications/test', auth, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM notification_settings WHERE user_id=$1', [req.user.id]);
    const s = rows[0];
    if (!s?.pushover_user_key) return res.status(400).json({ error: 'No notification settings found' });
    await pushNotify(s.pushover_user_key, s.pushover_api_token, { title: '🔔 Test', message: 'Network Tracker notifications are working!' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// AD SPEND
// ─────────────────────────────────────────
app.get('/api/spend', auth, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM ad_spend WHERE user_id=$1 ORDER BY spend_date DESC', [req.user.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/spend', auth, async (req, res) => {
  const { platform, campaign_id, offer_name, spend, spend_date } = req.body;
  try {
    const { rows } = await db.query(
      'INSERT INTO ad_spend (user_id,platform,campaign_id,offer_name,spend,spend_date) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.user.id, platform, campaign_id, offer_name, parseFloat(spend) || 0, spend_date || new Date().toISOString().split('T')[0]]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// STATS
// ─────────────────────────────────────────
app.get('/api/stats', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const isAdmin = req.user.role === 'admin';
    const uid = req.user.id;
    const uf = isAdmin ? '' : 'AND o.user_id=$2';
    const ufS = isAdmin ? '' : 'AND user_id=$2';
    const p = isAdmin ? [today] : [today, uid];
    const py = isAdmin ? [yesterday] : [yesterday, uid];
    const pA = isAdmin ? [] : [uid];

    const [t, total, clicks, platform, yest] = await Promise.all([
      db.query(`SELECT COUNT(*) as orders,COALESCE(SUM(payout),0) as revenue FROM orders o WHERE DATE(received_at)=$1 ${uf}`, p),
      db.query(`SELECT COUNT(*) as orders,COALESCE(SUM(payout),0) as revenue FROM orders o WHERE 1=1 ${uf.replace('AND o.','AND ')}`, pA),
      db.query(`SELECT COUNT(*) as clicks FROM clicks WHERE 1=1 ${ufS}`, pA),
      db.query(`SELECT c.traffic_source as source,COALESCE(SUM(o.payout),0) as revenue,COUNT(o.id) as orders FROM orders o LEFT JOIN clicks c ON o.click_id=c.click_id WHERE DATE(o.received_at)=$1 ${uf} GROUP BY c.traffic_source`, p),
      db.query(`SELECT COUNT(*) as orders,COALESCE(SUM(payout),0) as revenue FROM orders o WHERE DATE(received_at)=$1 ${uf}`, py)
    ]);

    const todayRev = parseFloat(t.rows[0].revenue);
    const todayOrd = parseInt(t.rows[0].orders);
    const totalRev = parseFloat(total.rows[0].revenue);
    const totalOrd = parseInt(total.rows[0].orders);
    const totalClk = parseInt(clicks.rows[0].clicks);
    const yRev = parseFloat(yest.rows[0].revenue);
    const yOrd = parseInt(yest.rows[0].orders);

    res.json({
      revenue_today: todayRev, orders_today: todayOrd,
      revenue_total: totalRev, total_orders: totalOrd, total_clicks: totalClk,
      conversion_rate: totalClk > 0 ? (totalOrd / totalClk * 100) : 0,
      revenue_change: yRev > 0 ? ((todayRev - yRev) / yRev * 100) : 0,
      orders_change: todayOrd - yOrd,
      by_platform: platform.rows
    });
  } catch(e) { console.error('Stats error:', e); res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// ORDERS
// ─────────────────────────────────────────
app.get('/api/orders', auth, async (req, res) => {
  try {
    const { period, limit = 200, offset = 0, search } = req.query;
    const isAdmin = req.user.role === 'admin';
    const uid = req.user.id;

    let df = '';
    if (period === 'today') df = "AND DATE(o.received_at)=CURRENT_DATE";
    else if (period === 'yesterday') df = "AND DATE(o.received_at)=CURRENT_DATE-1";
    else if (period === '7days') df = "AND o.received_at>=NOW()-INTERVAL '7 days'";
    else if (period === '30days') df = "AND o.received_at>=NOW()-INTERVAL '30 days'";
    else if (period === '6months') df = "AND o.received_at>=NOW()-INTERVAL '6 months'";
    else if (period === 'year') df = "AND o.received_at>=NOW()-INTERVAL '1 year'";

    let sf = '';
    if (search) sf = `AND o.transaction_id ILIKE '%${search.replace(/'/g, "''")}%'`;

    const uf = isAdmin ? '' : 'AND o.user_id=$3';
    const params = isAdmin ? [limit, offset] : [limit, offset, uid];

    const { rows } = await db.query(`
      SELECT o.id,o.transaction_id,o.payout,o.network,o.received_at,
        o.offer_name,o.landing_page_url,o.ad_creative,o.country,o.device_type,
        o.pixel_fired_fb,o.pixel_fired_tt,o.pixel_fired_snap,o.pixel_fired_google,
        c.traffic_source,c.campaign_id,c.ad_id,c.campaign_type
      FROM orders o
      LEFT JOIN clicks c ON o.click_id=c.click_id
      WHERE 1=1 ${df} ${sf} ${uf}
      ORDER BY o.received_at DESC LIMIT $1 OFFSET $2`, params);

    res.json(rows);
  } catch(e) { console.error('Orders error:', e); res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// ANALYTICS
// ─────────────────────────────────────────

app.get('/api/analytics/overview', auth, async (req, res) => {
  try {
    const { period = '30days', from, to } = req.query;
    const isAdmin = req.user.role === 'admin';
    const uid = req.user.id;
    const df = (from && to)
      ? `AND o.received_at >= '${from}' AND o.received_at <= '${to} 23:59:59'`
      : getPeriodFilter(period, 'o.received_at');
    const uf = isAdmin ? '' : 'AND o.user_id=$1';
    const params = isAdmin ? [] : [uid];

    const { rows } = await db.query(`
      SELECT o.offer_name,o.landing_page_url,o.ad_creative,o.country,o.device_type,
        c.traffic_source as platform,c.campaign_id,c.campaign_type,
        COUNT(o.id) as sales,COALESCE(SUM(o.payout),0) as revenue,AVG(o.payout) as avg_payout
      FROM orders o
      LEFT JOIN clicks c ON o.click_id=c.click_id
      WHERE 1=1 ${df} ${uf}
      GROUP BY o.offer_name,o.landing_page_url,o.ad_creative,o.country,o.device_type,c.traffic_source,c.campaign_id,c.campaign_type
      ORDER BY revenue DESC`, params);

    res.json(rows);
  } catch(e) { console.error('Analytics error:', e); res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// CLICK MAP
// ─────────────────────────────────────────
app.get('/api/clickmap', auth, async (req, res) => {
  try {
    const { period = '7days' } = req.query;
    const isAdmin = req.user.role === 'admin';
    const uid = req.user.id;
    const df = getPeriodFilter(period, 'c.created_at');
    const uf = isAdmin ? '' : 'AND c.user_id=$1';
    const params = isAdmin ? [] : [uid];

    const { rows } = await db.query(`
      SELECT c.campaign_id,c.ad_id,c.traffic_source,c.campaign_type,
        COUNT(c.id) as clicks,COUNT(o.id) as conversions,
        COALESCE(SUM(o.payout),0) as revenue,
        CASE WHEN COUNT(c.id)>0 THEN ROUND(COUNT(o.id)::numeric/COUNT(c.id)*100,2) ELSE 0 END as cvr
      FROM clicks c
      LEFT JOIN orders o ON c.click_id=o.click_id
      WHERE 1=1 ${df} ${uf}
      GROUP BY c.campaign_id,c.ad_id,c.traffic_source,c.campaign_type
      ORDER BY clicks DESC LIMIT 50`, params);

    res.json(rows);
  } catch(e) { console.error('Clickmap error:', e); res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// ROI
// ─────────────────────────────────────────
app.get('/api/roi', auth, async (req, res) => {
  try {
    const { period = '30days' } = req.query;
    const isAdmin = req.user.role === 'admin';
    const uid = req.user.id;
    const df = getPeriodFilter(period, 'o.received_at');
    const uf = isAdmin ? '' : 'AND o.user_id=$1';
    const params = isAdmin ? [] : [uid];

    const { rows } = await db.query(`
      SELECT COALESCE(o.offer_name,'Unknown') as offer_name,
        c.traffic_source as platform,
        COUNT(o.id) as sales,
        COALESCE(SUM(o.payout),0) as revenue,
        COALESCE(AVG(o.payout),0) as aov,
        COALESCE((SELECT SUM(spend) FROM ad_spend s WHERE s.offer_name=o.offer_name AND s.user_id=o.user_id),0) as spend,
        COALESCE(SUM(o.payout),0)-COALESCE((SELECT SUM(spend) FROM ad_spend s WHERE s.offer_name=o.offer_name AND s.user_id=o.user_id),0) as profit
      FROM orders o
      LEFT JOIN clicks c ON o.click_id=c.click_id
      WHERE 1=1 ${df} ${uf}
      GROUP BY o.offer_name,c.traffic_source,o.user_id
      ORDER BY revenue DESC`, params);

    res.json(rows);
  } catch(e) { console.error('ROI error:', e); res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────
// CLICK TRACKING
// ─────────────────────────────────────────
app.get('/track/click', async (req, res) => {
  const { click_id, source, campaign, campaign_type, adset, ad, fbclid, ttclid, gclid, snapclid, user_id } = req.query;
  try {
    await db.query(`
      INSERT INTO clicks (click_id,traffic_source,campaign_id,campaign_type,adset_id,ad_id,fbclid,ttclid,gclid,snapclid,ip,user_agent,user_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (click_id) DO NOTHING`,
      [click_id, source, campaign, campaign_type, adset, ad, fbclid, ttclid, gclid, snapclid, req.ip, req.headers['user-agent'], user_id || null]
    );
    res.send('OK');
  } catch(e) { res.status(500).send('Error'); }
});

// ─────────────────────────────────────────
// POSTBACK
// ─────────────────────────────────────────
app.get('/postback', async (req, res) => {
  const { click_id, payout, transaction_id, offer_id, network, offer_name, lp_url, creative, country, device } = req.query;
  try {
    const clickRes = await db.query('SELECT * FROM clicks WHERE click_id=$1', [click_id]);
    const click = clickRes.rows[0];

    await db.query(`
      INSERT INTO orders (click_id,network,offer_id,payout,transaction_id,offer_name,landing_page_url,ad_creative,country,device_type,user_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (transaction_id) DO NOTHING`,
      [click_id, network || 'unknown', offer_id, parseFloat(payout) || 0, transaction_id,
       offer_name || null, lp_url || null, creative || click?.ad_id || null,
       country || null, device || null, click?.user_id || null]
    );

    const [notifRow, pixelRows] = await Promise.all([
      click?.user_id ? db.query('SELECT * FROM notification_settings WHERE user_id=$1 AND enabled=TRUE', [click.user_id]) : { rows: [] },
      click?.user_id ? db.query('SELECT * FROM pixel_settings WHERE user_id=$1 AND enabled=TRUE', [click.user_id]) : { rows: [] }
    ]);

    await Promise.all([
      fireAllPixels(click_id, payout, transaction_id, click, pixelRows.rows, offer_name),
      notifRow.rows[0] ? pushNotify(notifRow.rows[0].pushover_user_key, notifRow.rows[0].pushover_api_token, {
        title: `🔥 Sale — +$${parseFloat(payout).toFixed(2)}`,
        message: `Source: ${click?.traffic_source || 'Unknown'}\nCampaign: ${click?.campaign_id || '–'}\nNetwork: ${network || '–'}`
      }) : Promise.resolve()
    ]);

    res.send('OK');
  } catch(e) { console.error('Postback error:', e.message); res.status(500).send('Error'); }
});

// ─────────────────────────────────────────
// FIRE ALL PIXELS
// ─────────────────────────────────────────
async function fireAllPixels(click_id, payout, transaction_id, click = {}, pixelSettings = [], offer_name = null) {
  // Get assigned pixels for this offer
  let assignedPixels = pixelSettings;
  if (offer_name && click?.user_id) {
    const assignments = await db.query(`
      SELECT ps.* FROM offer_pixel_assignments opa
      JOIN pixel_settings ps ON opa.pixel_setting_id=ps.id
      WHERE opa.user_id=$1 AND opa.offer_name=$2 AND ps.enabled=TRUE`,
      [click.user_id, offer_name]
    );
    if (assignments.rows.length > 0) assignedPixels = assignments.rows;
  }

  for (const px of assignedPixels) {
    if (px.platform === 'meta' || px.platform === 'facebook') {
      await fireFBCAPI(px.pixel_id, px.access_token, payout, transaction_id, click);
      await db.query('UPDATE orders SET pixel_fired_fb=TRUE WHERE transaction_id=$1', [transaction_id]);
    }
    if (px.platform === 'tiktok') {
      await fireTikTok(px.pixel_id, px.access_token, payout, transaction_id, click);
      await db.query('UPDATE orders SET pixel_fired_tt=TRUE WHERE transaction_id=$1', [transaction_id]);
    }
    if (px.platform === 'snapchat') {
      await fireSnap(px.pixel_id, px.access_token, payout, transaction_id, click);
      await db.query('UPDATE orders SET pixel_fired_snap=TRUE WHERE transaction_id=$1', [transaction_id]);
    }
    if (px.platform === 'google') {
      await fireGoogle(px.pixel_id, px.access_token, payout, transaction_id, click);
      await db.query('UPDATE orders SET pixel_fired_google=TRUE WHERE transaction_id=$1', [transaction_id]);
    }
  }
}

async function fireFBCAPI(pixelId, token, payout, transaction_id, click) {
  try {
    await fetch(`https://graph.facebook.com/v18.0/${pixelId}/events?access_token=${token}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: [{ event_name: 'Purchase', event_time: Math.floor(Date.now() / 1000), event_id: transaction_id, action_source: 'website', custom_data: { value: parseFloat(payout), currency: 'USD' }, user_data: { fbc: click?.fbclid ? `fb.1.${Date.now()}.${click.fbclid}` : undefined, client_ip_address: click?.ip, client_user_agent: click?.user_agent } }] })
    });
  } catch(e) { console.error('FB CAPI error:', e.message); }
}

async function fireTikTok(pixelId, token, payout, transaction_id, click) {
  try {
    await fetch('https://business-api.tiktok.com/open_api/v1.3/event/track/', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Access-Token': token },
      body: JSON.stringify({ pixel_code: pixelId, event: 'CompletePayment', event_id: transaction_id, timestamp: new Date().toISOString(), properties: { value: parseFloat(payout), currency: 'USD' }, context: { ip: click?.ip, user_agent: click?.user_agent, ttclid: click?.ttclid } })
    });
  } catch(e) { console.error('TikTok error:', e.message); }
}

async function fireSnap(pixelId, token, payout, transaction_id, click) {
  try {
    await fetch('https://tr.snapchat.com/v2/conversion', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ pixel_id: pixelId, event_type: 'PURCHASE', event_conversion_type: 'WEB', timestamp: Date.now(), hashed_data: { client_ip_address: click?.ip, client_user_agent: click?.user_agent }, user_data: { sc_click_id: click?.snapclid }, custom_data: { currency: 'USD', price: parseFloat(payout), transaction_id } })
    });
  } catch(e) { console.error('Snap CAPI error:', e.message); }
}

async function fireGoogle(conversionId, token, payout, transaction_id, click) {
  try {
    await fetch(`https://googleads.googleapis.com/v14/customers/${conversionId}:uploadClickConversions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, 'developer-token': process.env.GOOGLE_DEVELOPER_TOKEN || '' },
      body: JSON.stringify({ conversions: [{ gclid: click?.gclid, conversionDateTime: new Date().toISOString().replace('T', ' ').replace('Z', '+00:00'), conversionValue: parseFloat(payout), currencyCode: 'USD', orderId: transaction_id }], partialFailure: true })
    });
  } catch(e) { console.error('Google Ads error:', e.message); }
}

async function pushNotify(userKey, apiToken, { title, message }) {
  try {
    await fetch('https://api.pushover.net/1/messages.json', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: apiToken, user: userKey, title, message, sound: 'cashregister', priority: 1 })
    });
  } catch(e) { console.error('Pushover error:', e.message); }
}

function getPeriodFilter(period, field) {
  if (period === 'today') return `AND DATE(${field})=CURRENT_DATE`;
  if (period === 'yesterday') return `AND DATE(${field})=CURRENT_DATE-1`;
  if (period === '7days') return `AND ${field}>=NOW()-INTERVAL '7 days'`;
  if (period === '6months') return `AND ${field}>=NOW()-INTERVAL '6 months'`;
  if (period === 'year') return `AND ${field}>=NOW()-INTERVAL '1 year'`;
  return `AND ${field}>=NOW()-INTERVAL '30 days'`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Tracker running on port ${PORT}`));

// ─────────────────────────────────────────
// ANALYTICS V2 — full breakdown
// ─────────────────────────────────────────
app.get('/api/analytics/overview', auth, async (req, res) => {
  try {
    const { period = '30days' } = req.query;
    const isAdmin = req.user.role === 'admin';
    const uid = req.user.id;
    const df = getPeriodFilter(period, 'o.received_at');
    const uf = isAdmin ? '' : 'AND o.user_id=$1';
    const params = isAdmin ? [] : [uid];

    const [summary, daily, offers, campaigns, networks, countries, platforms] = await Promise.all([
      db.query(`SELECT COUNT(*) as sales, COALESCE(SUM(payout),0) as revenue, COALESCE(AVG(payout),0) as aov FROM orders o WHERE 1=1 ${df} ${uf}`, params),
      db.query(`SELECT DATE(o.received_at) as date, COUNT(*) as sales, COALESCE(SUM(payout),0) as revenue FROM orders o WHERE 1=1 ${df} ${uf} GROUP BY DATE(o.received_at) ORDER BY date ASC`, params),
      db.query(`SELECT COALESCE(o.offer_name,'Unknown') as name, COUNT(*) as sales, COALESCE(SUM(payout),0) as revenue, COALESCE(AVG(payout),0) as aov FROM orders o WHERE 1=1 ${df} ${uf} GROUP BY o.offer_name ORDER BY revenue DESC LIMIT 10`, params),
      db.query(`SELECT COALESCE(c.campaign_id,'Unknown') as name, c.traffic_source as platform, COUNT(o.id) as sales, COALESCE(SUM(o.payout),0) as revenue, COALESCE(AVG(o.payout),0) as aov FROM orders o LEFT JOIN clicks c ON o.click_id=c.click_id WHERE 1=1 ${df} ${uf} GROUP BY c.campaign_id, c.traffic_source ORDER BY revenue DESC LIMIT 10`, params),
      db.query(`SELECT COALESCE(o.network,'Unknown') as name, COUNT(*) as sales, COALESCE(SUM(payout),0) as revenue FROM orders o WHERE 1=1 ${df} ${uf} GROUP BY o.network ORDER BY revenue DESC`, params),
      db.query(`SELECT COALESCE(o.country,'Unknown') as name, COUNT(*) as sales, COALESCE(SUM(payout),0) as revenue FROM orders o WHERE 1=1 ${df} ${uf} GROUP BY o.country ORDER BY revenue DESC LIMIT 10`, params),
      db.query(`SELECT COALESCE(c.traffic_source,'Unknown') as name, COUNT(o.id) as sales, COALESCE(SUM(o.payout),0) as revenue FROM orders o LEFT JOIN clicks c ON o.click_id=c.click_id WHERE 1=1 ${df} ${uf} GROUP BY c.traffic_source ORDER BY revenue DESC`, params)
    ]);

    // clicks for CVR
    const clicksQ = isAdmin
      ? await db.query(`SELECT COUNT(*) as clicks FROM clicks WHERE 1=1 ${df.replace('o.received_at','created_at')}`)
      : await db.query(`SELECT COUNT(*) as clicks FROM clicks WHERE 1=1 ${df.replace('o.received_at','created_at')} AND user_id=$1`, [uid]);

    const totalSales = parseInt(summary.rows[0].sales);
    const totalClicks = parseInt(clicksQ.rows[0].clicks);

    res.json({
      summary: {
        ...summary.rows[0],
        clicks: totalClicks,
        cvr: totalClicks > 0 ? (totalSales / totalClicks * 100).toFixed(2) : 0
      },
      daily: daily.rows,
      offers: offers.rows,
      campaigns: campaigns.rows,
      networks: networks.rows,
      countries: countries.rows,
      platforms: platforms.rows
    });
  } catch(e) { console.error('Analytics overview error:', e); res.status(500).json({ error: e.message }); }
});