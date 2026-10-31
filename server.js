import express from 'express';
import helmet from 'helmet';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const { Pool } = pg;
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProd = process.env.NODE_ENV === 'production';
const required = ['DATABASE_URL', 'SESSION_SECRET', 'ADMIN_EMAIL', 'ADMIN_PASSWORD_HASH'];
const missing = required.filter(k => !process.env[k]);
if (missing.length) { console.error(`Missing required environment variables: ${missing.join(', ')}`); process.exit(1); }
if (process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters.');
if (!/^\$2[aby]\$\d\d\$/.test(process.env.ADMIN_PASSWORD_HASH)) throw new Error('ADMIN_PASSWORD_HASH must be a bcrypt hash.');
if (isProd && !process.env.DATABASE_URL.startsWith('postgres')) throw new Error('DATABASE_URL must point to PostgreSQL.');
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, referrerPolicy: { policy: 'strict-origin-when-cross-origin' } }));
app.use(express.json({ limit: '3mb' }));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'disable' ? false : (isProd ? { rejectUnauthorized: false } : undefined) });
const PgStore = connectPgSimple(session);

const DEFAULT_PRODUCTS = [
  { id: 'p1', name: 'شمع استوانه‌ای معطر', cat: 'شمع', desc: 'شمع دست‌ساز با رایحه ملایم، مناسب میز پذیرایی و هدیه.', retail: 185000, wholesale: 130000, minQty: 12, inStock: true, status: 'published', img: '' },
  { id: 'p2', name: 'شمع ژله‌ای رنگی', cat: 'شمع', desc: 'شمع ژله‌ای شفاف در رنگ‌های صورتی و آبی.', retail: 120000, wholesale: 85000, minQty: 12, inStock: true, status: 'published', img: '' },
  { id: 'p3', name: 'سنگ مصنوعی رزینی صورتی', cat: 'سنگ مصنوعی', desc: 'سنگ دکوری رزینی با رنگ صورتی ملایم.', retail: 95000, wholesale: 60000, minQty: 20, inStock: true, status: 'published', img: '' },
  { id: 'p4', name: 'سنگ مصنوعی آبی دریایی', cat: 'سنگ مصنوعی', desc: 'سنگ دکوری مناسب گلدان، آکواریوم و تزئین سفره.', retail: 95000, wholesale: 60000, minQty: 20, inStock: true, status: 'published', img: '' }
];
const DEFAULT_SETTINGS = { instagram: 'https://www.instagram.com/hinahome', phone: '', wholesaleNote: 'خرید عمده با قیمت ویژه و حداقل تعداد برای هر محصول. تعداد لازم زیر هر محصول نوشته شده است.' };
const DEFAULT_OCCASIONS = [];
const emailNorm = e => String(e || '').trim().toLowerCase();
const validEmail = e => typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 254;
const passwordOk = p => typeof p === 'string' && p.length >= 10 && p.length <= 128;
// SHA-256 pre-hash prevents bcrypt's 72-byte input truncation for long passwords.
const passwordInput = p => crypto.createHash('sha256').update(p, 'utf8').digest('hex');
const allowedKeys = new Set(['products','orders','occasions','settings']);
const sameOrigin = (req, res, next) => {
  const origin = req.get('origin');
  if (origin) {
    const expected = `${req.protocol}://${req.get('host')}`;
    if (origin !== expected) return res.status(403).json({ error: 'درخواست نامعتبر است.' });
  } else if (isProd && ['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    return res.status(403).json({ error: 'مبدأ درخواست قابل تأیید نیست.' });
  }
  next();
};
const requireAuth = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: 'ابتدا وارد حساب شوید.' });
const requireAdmin = (req, res, next) => req.session.user?.role === 'admin' ? next() : res.status(403).json({ error: 'دسترسی مدیریت ندارید.' });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'تلاش‌های زیادی انجام شده؛ ۱۵ دقیقه دیگر دوباره امتحان کنید.' } });
const orderLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'تعداد سفارش‌ها زیاد است؛ کمی بعد دوباره تلاش کنید.' } });

await pool.query(`
 CREATE TABLE IF NOT EXISTS users (
   id BIGSERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
   role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 );
 CREATE TABLE IF NOT EXISTS site_data (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
`);
for (const [key, value] of Object.entries({ products: DEFAULT_PRODUCTS, settings: DEFAULT_SETTINGS, occasions: DEFAULT_OCCASIONS, orders: [] })) {
  await pool.query('INSERT INTO site_data(key,value) VALUES($1,$2::jsonb) ON CONFLICT(key) DO NOTHING', [key, JSON.stringify(value)]);
}
app.use(session({
  name: 'hina.sid', store: new PgStore({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 12, path: '/' }
}));
const readData = async key => (await pool.query('SELECT value FROM site_data WHERE key=$1', [key])).rows[0]?.value;
const writeData = async (key, value) => pool.query('INSERT INTO site_data(key,value,updated_at) VALUES($1,$2::jsonb,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()', [key, JSON.stringify(value)]);

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});
app.get('/api/auth/me', (req, res) => res.json({ user: req.session.user || null }));
app.post('/api/auth/register', authLimiter, sameOrigin, async (req, res, next) => {
  try {
    const email = emailNorm(req.body?.email), password = req.body?.password;
    if (!validEmail(email)) return res.status(400).json({ error: 'ایمیل معتبر نیست.' });
    if (!passwordOk(password)) return res.status(400).json({ error: 'رمز باید بین ۱۰ تا ۱۲۸ کاراکتر باشد.' });
    if (email === emailNorm(process.env.ADMIN_EMAIL)) return res.status(403).json({ error: 'این ایمیل برای حساب مدیریت رزرو شده است.' });
    const hash = await bcrypt.hash(passwordInput(password), 12);
    let result;
    try { result = await pool.query('INSERT INTO users(email,password_hash,role) VALUES($1,$2,$3) RETURNING id,email,role', [email, hash, 'user']); }
    catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'این ایمیل قبلاً ثبت‌نام کرده است؛ وارد حساب شوید.' }); throw e; }
    await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
    req.session.user = { id: String(result.rows[0].id), email: result.rows[0].email, role: 'user' };
    await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
    res.status(201).json({ user: req.session.user });
  } catch (e) { next(e); }
});
app.post('/api/auth/login', authLimiter, sameOrigin, async (req, res, next) => {
  try {
    const email = emailNorm(req.body?.email), password = req.body?.password;
    if (!validEmail(email) || typeof password !== 'string' || password.length > 128) return res.status(400).json({ error: 'ایمیل یا رمز نامعتبر است.' });
    let user;
    if (email === emailNorm(process.env.ADMIN_EMAIL)) {
      const ok = await bcrypt.compare(passwordInput(password), process.env.ADMIN_PASSWORD_HASH);
      if (!ok) return res.status(401).json({ error: 'ایمیل یا رمز اشتباه است.' });
      user = { id: 'admin', email, role: 'admin' };
    } else {
      const r = await pool.query('SELECT id,email,password_hash,role FROM users WHERE email=$1', [email]);
      const u = r.rows[0];
      // Do a comparable hash operation even when the email is unknown to reduce timing-based account enumeration.
      const ok = await bcrypt.compare(passwordInput(password), u?.password_hash || process.env.ADMIN_PASSWORD_HASH).catch(() => false);
      if (!u || !ok || u.role !== 'user') return res.status(401).json({ error: 'ایمیل یا رمز اشتباه است.' });
      user = { id: String(u.id), email: u.email, role: 'user' };
    }
    await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
    req.session.user = user;
    await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
    res.json({ user });
  } catch (e) { next(e); }
});
app.post('/api/auth/logout', sameOrigin, (req, res, next) => req.session.destroy(e => {
  if (e) return next(e);
  res.clearCookie('hina.sid', { httpOnly: true, secure: isProd, sameSite: 'lax', path: '/' }); res.json({ ok: true });
}));

app.get('/api/storefront', async (_req, res, next) => {
  try {
    const [products, settings, occasions] = await Promise.all([readData('products'), readData('settings'), readData('occasions')]);
    res.set('Cache-Control', 'no-store'); res.json({ products: (products || []).filter(p => p.status === 'published'), settings: settings || DEFAULT_SETTINGS, occasions: occasions || [] });
  } catch (e) { next(e); }
});
app.post('/api/orders', requireAuth, orderLimiter, sameOrigin, async (req, res, next) => {
  try {
    const { name, phone, addr, mode, items } = req.body || {};
    const cleanName = typeof name === 'string' ? name.trim().slice(0,120) : '';
    const cleanPhone = typeof phone === 'string' ? phone.replace(/[\s()-]/g,'').slice(0,20) : '';
    const cleanAddr = typeof addr === 'string' ? addr.trim().slice(0,1000) : '';
    if (!cleanName || !/^0?9\d{9}$|^0\d{10}$/.test(cleanPhone) || !cleanAddr) return res.status(400).json({ error: 'نام، شماره تماس درست و آدرس را کامل بنویسید.' });
    if (!['retail','wholesale'].includes(mode) || !Array.isArray(items) || items.length < 1 || items.length > 50) return res.status(400).json({ error: 'سبد خرید نامعتبر است.' });
    const products = await readData('products') || [];
    const orderItems = [];
    for (const item of items) {
      const p = products.find(x => x.id === String(item?.id) && x.status === 'published');
      const qty = Number(item?.qty);
      if (!p || !p.inStock || !Number.isSafeInteger(qty) || qty < 1 || qty > 10000) return res.status(400).json({ error: 'یکی از محصولات یا تعداد آن نامعتبر است.' });
      if (mode === 'wholesale' && qty < Math.max(1, Number(p.minQty) || 1)) return res.status(400).json({ error: `حداقل خرید عمده «${p.name}» ${Math.max(1, Number(p.minQty)||1)} عدد است.` });
      const unit = Number(mode === 'wholesale' ? p.wholesale : p.retail);
      if (!Number.isSafeInteger(unit) || unit <= 0) return res.status(400).json({ error: `قیمت این محصول برای خرید ${mode === 'wholesale' ? 'عمده' : 'تکی'} معتبر نیست.` });
      orderItems.push({ id: p.id, name: String(p.name).slice(0,200), qty, unit });
    }
    const total = orderItems.reduce((sum, i) => sum + i.qty * i.unit, 0);
    if (!Number.isSafeInteger(total) || total <= 0 || total > 1_000_000_000_000) return res.status(400).json({ error: 'مبلغ سفارش نامعتبر است.' });
    // Serialize order appends to avoid two simultaneous orders overwriting each other.
    const client = await pool.connect();
    let order;
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('hina-home-orders'))");
      const q = await client.query("SELECT value FROM site_data WHERE key='orders' FOR UPDATE");
      const orders = Array.isArray(q.rows[0]?.value) ? q.rows[0].value : [];
      order = { id: 'o' + crypto.randomUUID(), email: req.session.user.email, mode, items: orderItems, total, name: cleanName, phone: cleanPhone, addr: cleanAddr, status: 'جدید', date: Date.now() };
      orders.unshift(order);
      await client.query("INSERT INTO site_data(key,value,updated_at) VALUES('orders',$1::jsonb,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()", [JSON.stringify(orders)]);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    res.status(201).json({ ok: true, orderId: order.id });
  } catch (e) { next(e); }
});
app.get('/api/admin/data/:key', requireAdmin, async (req, res, next) => {
  try {
    const key = req.params.key;
    if (key === 'users') {
      const r = await pool.query('SELECT id,email,role,created_at FROM users ORDER BY created_at DESC');
      return res.json({ value: r.rows.map(u => ({ id: String(u.id), email: u.email, role: u.role, createdAt: new Date(u.created_at).getTime() })) });
    }
    if (!allowedKeys.has(key)) return res.status(404).json({ error: 'یافت نشد.' });
    res.set('Cache-Control','no-store'); res.json({ value: (await readData(key)) ?? null });
  } catch (e) { next(e); }
});
app.put('/api/admin/data/:key', requireAdmin, sameOrigin, async (req, res, next) => {
  try {
    const key = req.params.key;
    if (!allowedKeys.has(key)) return res.status(404).json({ error: 'یافت نشد.' });
    const value = req.body?.value;
    if (value === undefined || Buffer.byteLength(JSON.stringify(value)) > 2_500_000) return res.status(400).json({ error: 'داده نامعتبر یا بیش از حد بزرگ است.' });
    if (key === 'products' && (!Array.isArray(value) || value.length > 1000)) return res.status(400).json({ error: 'فهرست محصولات نامعتبر است.' });
    if (key === 'orders' && (!Array.isArray(value) || value.length > 10000)) return res.status(400).json({ error: 'فهرست سفارش‌ها نامعتبر است.' });
    if (key === 'settings' && (!value || typeof value !== 'object' || Array.isArray(value))) return res.status(400).json({ error: 'تنظیمات نامعتبر است.' });
    if (key === 'occasions' && (!Array.isArray(value) || value.length > 500)) return res.status(400).json({ error: 'فهرست مناسبت‌ها نامعتبر است.' });
    await writeData(key, value); res.json({ ok: true });
  } catch (e) { next(e); }
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: isProd ? '1h' : 0 }));
app.use((err, _req, res, _next) => {
  // Avoid exposing database errors, SQL, credentials, or stack traces to clients.
  console.error(err?.message || 'Unexpected server error');
  if (res.headersSent) return;
  res.status(500).json({ error: 'خطای داخلی سرور؛ لطفاً کمی بعد دوباره تلاش کنید.' });
});
export default app;

