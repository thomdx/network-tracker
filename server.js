const express = require('express');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

const db = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ─────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────
app.get('/health', (req, res) => {
  res.send('Tracker is running ✓');
});

// ─────────────────────────────────────────
// API — STATS for dashboard
// ─────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];

    const [todayStats, totalStats, clickStats, platformStats, yesterdayStats] = await Promise.all([

      // Today's orders
      db.query(`
        SELECT COUNT(*) as orders, COALESCE(SUM(payout), 0) as revenue
        FROM orders
        WHERE DATE(received_at) = $1
      `, [today]),

      // All time totals
      db.query(`
        SELECT COUNT(*) as orders, COALESCE(SUM(payout), 0) as revenue
        FROM orders
      `),

      // Total clicks
      db.query(`SELECT COUNT(*) as clicks FROM clicks`),

      // Revenue by platform
      db.query(`
        SELECT c.traffic_source as source, COALESCE(SUM(o.payout), 0) as revenue, COUNT(o.id) as orders
        FROM orders o
        LEFT JOIN clicks c ON o.click_id = c.click_id
        WHERE DATE(o.received_at) = $1
        GROUP BY c.traffic_source
      `, [today]),

      // Yesterday's stats for comparison
      db.query(`
        SELECT COUNT(*) as orders, COALESCE(SUM(payout), 0) as revenue
        FROM orders
        WHERE DATE(received_at) = $1
      `, [new Date(Date.now() - 86400000).toISOString().split('T')[0]])
    ]);

    const todayRev   = parseFloat(todayStats.rows[0].revenue);
    const todayOrd   = parseInt(todayStats.rows[0].orders);
    const totalRev   = parseFloat(totalStats.rows[0].revenue);
    const totalOrd   = parseInt(totalStats.rows[0].orders);
    const totalClk   = parseInt(clickStats.rows[0].clicks);
    const yesterdayRev = parseFloat(yesterdayStats.rows[0].revenue);
    const yesterdayOrd = parseInt(yesterdayStats.rows[0].orders);

    res.json({
      revenue_today:    todayRev,
      orders_today:     todayOrd,
      revenue_total:    totalRev,
      total_orders:     totalOrd,
      total_clicks:     totalClk,
      conversion_rate:  totalClk > 0 ? (totalOrd / totalClk * 100) : 0,
      revenue_change:   yesterdayRev > 0 ? ((todayRev - yesterdayRev) / yesterdayRev * 100) : 0,
      orders_change:    todayOrd - yesterdayOrd,
      by_platform:      platformStats.rows
    });

  }  catch(e) {
    console.error('Stats error full:', e);
    res.status(500).json({ error: e.message, detail: e.toString() });
  }
});

// ─────────────────────────────────────────
// API — RECENT ORDERS for dashboard table
// ─────────────────────────────────────────
app.get('/api/orders', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;

    const { rows } = await db.query(`
      SELECT 
        o.transaction_id,
        o.payout,
        o.network,
        o.received_at,
        o.pixel_fired_fb,
        o.pixel_fired_tt,
        c.traffic_source,
        c.campaign_id
      FROM orders o
      LEFT JOIN clicks c ON o.click_id = c.click_id
      ORDER BY o.received_at DESC
      LIMIT $1
    `, [limit]);

    res.json(rows);
  } catch(e) {
    console.error('Orders error full:', e);
    res.status(500).json({ error: e.message, detail: e.toString() });
  }
});

// ─────────────────────────────────────────
// ENDPOINT 1 — Log click from landing page
// ─────────────────────────────────────────
app.get('/track/click', async (req, res) => {
  const { click_id, source, campaign, adset, ad, fbclid, ttclid, gclid } = req.query;
  try {
    await db.query(`
      INSERT INTO clicks
        (click_id, traffic_source, campaign_id, adset_id, ad_id, fbclid, ttclid, gclid, ip, user_agent)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT (click_id) DO NOTHING`,
      [click_id, source, campaign, adset, ad, fbclid, ttclid, gclid, req.ip, req.headers['user-agent']]
    );
    res.send('OK');
  } catch(e) {
    console.error('Click error:', e.message);
    res.status(500).send('Error');
  }
});

// ─────────────────────────────────────────
// ENDPOINT 2 — Receive postback from network
// ─────────────────────────────────────────
app.get('/postback', async (req, res) => {
  const { click_id, payout, transaction_id, offer_id, network } = req.query;
  try {
    await db.query(`
      INSERT INTO orders
        (click_id, network, offer_id, payout, transaction_id)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (transaction_id) DO NOTHING`,
      [click_id, network || 'unknown', offer_id, parseFloat(payout) || 0, transaction_id]
    );

    const { rows } = await db.query(
      'SELECT * FROM clicks WHERE click_id = $1', [click_id]
    );

    await Promise.all([
      firePixels(click_id, payout, transaction_id),
      notifyPhone({ payout, network, transaction_id }, rows[0])
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
async function firePixels(click_id, payout, transaction_id) {
  const { rows } = await db.query(
    'SELECT * FROM clicks WHERE click_id = $1', [click_id]
  );
  const click = rows[0] || {};

  // Facebook CAPI
  try {
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
            custom_data: {
              value: parseFloat(payout),
              currency: 'USD'
            },
            user_data: {
              fbc: click.fbclid ? `fb.1.${Date.now()}.${click.fbclid}` : undefined,
              client_ip_address: click.ip,
              client_user_agent: click.user_agent
            }
          }]
        })
      }
    );
    await db.query(
      'UPDATE orders SET pixel_fired_fb = TRUE WHERE transaction_id = $1',
      [transaction_id]
    );
  } catch(e) { console.error('FB CAPI error:', e.message); }

  // TikTok Events API
  try {
    await fetch('https://business-api.tiktok.com/open_api/v1.3/event/track/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Access-Token': process.env.TT_ACCESS_TOKEN
      },
      body: JSON.stringify({
        pixel_code: process.env.TT_PIXEL_ID,
        event: 'CompletePayment',
        event_id: transaction_id,
        timestamp: new Date().toISOString(),
        properties: { value: parseFloat(payout), currency: 'USD' },
        context: { ip: click.ip, user_agent: click.user_agent, ttclid: click.ttclid }
      })
    });
    await db.query(
      'UPDATE orders SET pixel_fired_tt = TRUE WHERE transaction_id = $1',
      [transaction_id]
    );
  } catch(e) { console.error('TikTok error:', e.message); }
}

// ─────────────────────────────────────────
// NOTIFY PHONE
// ─────────────────────────────────────────
async function notifyPhone(order, click) {
  try {
    const source   = click?.traffic_source || 'Unknown';
    const campaign = click?.campaign_id    || '–';
    const payout   = parseFloat(order.payout || 0).toFixed(2);

    await fetch('https://api.pushover.net/1/messages.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token:    process.env.PUSHOVER_API_TOKEN,
        user:     process.env.PUSHOVER_USER_KEY,
        title:    `🔥 Sale Confirmed — +$${payout}`,
        message:  `Source: ${source}\nCampaign: ${campaign}\nNetwork: ${order.network}`,
        sound:    'cashregister',
        priority: 1
      })
    });
  } catch(e) { console.error('Pushover error:', e.message); }
}

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Tracker running on port ${PORT}`);
});