const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const envFile = path.join(__dirname, '.env');
const envExample = path.join(__dirname, '.env.example');
loadEnv(fs.existsSync(envFile) ? envFile : envExample);

const app = express();
const PORT = process.env.PORT || 3000;
const pool = new Pool({
  host: process.env.PGHOST || '127.0.0.1',
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE || 'WebLab',
});

app.use(express.urlencoded({ extended: true, limit: '32kb' }));
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser());

app.get(['/login.html', '/register.html'], asyncRoute(async (req, res, next) => {
  if (await currentUser(req)) return res.redirect('/welcome');
  next();
}));

app.use(express.static(path.join(__dirname, 'public')));

const RULES = {
  login: /^[A-Za-z0-9_]{3,20}$/,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  password: /^(?=.*[A-Za-z])(?=.*\d).{6,128}$/,
};

const LIMITS = { email: 254, password: 128 };

const USER_COOKIE = {
  maxAge: 1000 * 60 * 60,
  httpOnly: false,
  sameSite: 'lax',
  path: '/',
};

function asString(value, trim) {
  if (typeof value !== 'string') return '';
  return trim ? value.trim() : value;
}

function fieldsFrom(body) {
  const src = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  return {
    login: asString(src.login, true),
    email: asString(src.email, true),
    password: asString(src.password, false),
  };
}

function formatErrors({ login, email, password }) {
  const errors = [];
  if (!RULES.login.test(login)) {
    errors.push('Логин: от 3 до 20 символов, только латинские буквы, цифры и "_".');
  }
  if (!email || email.length > LIMITS.email || /[<>"']/.test(email) || !RULES.email.test(email)) {
    errors.push('Введите корректный email, например name@example.com.');
  }
  if (!RULES.password.test(password)) {
    errors.push('Пароль: от 6 до 128 символов, хотя бы одна буква и одна цифра.');
  }
  return errors;
}

async function findByLogin(login) {
  const { rows } = await pool.query(
    'SELECT login, email, password_hash FROM users WHERE LOWER(login) = LOWER($1)',
    [login]
  );
  return rows[0] || null;
}

async function emailTaken(email) {
  const { rows } = await pool.query(
    'SELECT 1 FROM users WHERE LOWER(email) = LOWER($1)',
    [email]
  );
  return rows.length > 0;
}

async function currentUser(req) {
  const login = asString(req.cookies && req.cookies.user, false);
  if (!login) return null;
  const { rows } = await pool.query(
    'SELECT login, email FROM users WHERE login = $1',
    [login]
  );
  return rows[0] || null;
}

app.get('/', asyncRoute(async (req, res) => {
  res.redirect(await currentUser(req) ? '/welcome' : '/register.html');
}));

app.get('/favicon.ico', (req, res) => {
  res.redirect(302, '/logo.png');
});

app.get('/api/check-login', asyncRoute(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  const raw = req.query.login;
  const login = asString(Array.isArray(raw) ? raw[0] : raw, true).slice(0, 100);
  const valid = RULES.login.test(login);
  const taken = valid && Boolean(await findByLogin(login));
  res.json({ valid, available: valid && !taken });
}));

app.post('/register', asyncRoute(async (req, res) => {
  const { login, email, password } = fieldsFrom(req.body);
  const errors = formatErrors({ login, email, password });

  if (!errors.length && await findByLogin(login)) {
    errors.push('Такой логин уже занят.');
  }
  if (!errors.some((item) => item.includes('email')) && email && await emailTaken(email)) {
    errors.push('Этот email уже зарегистрирован.');
  }

  if (errors.length > 0) {
    return res.status(400).send(renderPage({
      title: 'Ошибка регистрации',
      body: `
        <h1>Не получилось зарегистрироваться</h1>
        <ul class="errors">
          ${errors.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
        </ul>
        <a class="button" href="/register.html">Назад к форме</a>
      `,
    }));
  }

  const passwordHash = await bcrypt.hash(password, 10);
  try {
    await pool.query(
      'INSERT INTO users (login, email, password_hash) VALUES ($1, $2, $3)',
      [login, email, passwordHash]
    );
  } catch (err) {
    if (err.code === '23505') {
      const message = String(err.constraint).includes('email')
        ? 'Этот email уже зарегистрирован.'
        : 'Такой логин уже занят.';
      return res.status(400).send(renderPage({
        title: 'Ошибка регистрации',
        body: `
          <h1>Не получилось зарегистрироваться</h1>
          <ul class="errors"><li>${escapeHtml(message)}</li></ul>
          <a class="button" href="/register.html">Назад к форме</a>
        `,
      }));
    }
    throw err;
  }

  res.cookie('user', login, USER_COOKIE);
  res.redirect('/welcome');
}));

app.post('/login', asyncRoute(async (req, res) => {
  const { login, password } = fieldsFrom(req.body);
  const user = RULES.login.test(login) ? await findByLogin(login) : null;
  const ok = Boolean(user) && await bcrypt.compare(password, user.password_hash);

  if (!ok) {
    return res.status(400).send(renderPage({
      title: 'Ошибка входа',
      body: `
        <h1>Не получилось войти</h1>
        <ul class="errors">
          <li>Неверный логин или пароль.</li>
        </ul>
        <a class="button" href="/login.html">Назад ко входу</a>
        <p class="switch">Нет аккаунта? <a href="/register.html">Зарегистрироваться</a></p>
      `,
    }));
  }

  res.cookie('user', user.login, USER_COOKIE);
  res.redirect('/welcome');
}));

app.get('/welcome', asyncRoute(async (req, res) => {
  const login = asString(req.cookies.user, false);
  if (!login) return res.redirect('/login.html');

  const user = await currentUser(req);
  const emailLine = user
    ? `Вы зарегистрированы с адресом ${escapeHtml(user.email)}.`
    : 'Кука на месте, но такого пользователя в базе WebLab нет. Войдите ещё раз.';

  res.send(renderPage({
    title: 'Добро пожаловать',
    body: `
      <img src="/logo.png" alt="Логотип" class="logo">
      <h1>С возвращением, ${escapeHtml(login)}!</h1>
      <p class="muted">${emailLine}</p>
      <p class="muted">Ваш логин хранится в cookie <code>user</code> — поэтому страница узнаёт вас, пока кука жива (1 час).</p>
      <a class="button secondary" href="/logout">Выйти</a>
    `,
  }));
}));

app.get('/logout', (req, res) => {
  res.clearCookie('user', {
    httpOnly: USER_COOKIE.httpOnly,
    sameSite: USER_COOKIE.sameSite,
    path: USER_COOKIE.path,
  });
  res.redirect('/login.html');
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderPage({ title, body }) {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
  <link rel="icon" href="/logo.png" type="image/png">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <main class="card">
    ${body}
  </main>
</body>
</html>`;
}

function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function quoteIdent(name) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error('Некорректное имя базы данных.');
  }
  return `"${name}"`;
}

async function prepareDatabase() {
  const admin = new Pool({
    host: process.env.PGHOST || '127.0.0.1',
    port: Number(process.env.PGPORT || 5432),
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD,
    database: 'postgres',
  });
  const name = process.env.PGDATABASE || 'WebLab';
  try {
    const found = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (!found.rowCount) {
      await admin.query(`CREATE DATABASE ${quoteIdent(name)}`);
    }
  } finally {
    await admin.end();
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      login varchar(20) NOT NULL,
      email varchar(254) NOT NULL,
      password_hash text NOT NULL
    )
  `);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_login_key ON users (LOWER(login))');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (LOWER(email))');
}

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (key && process.env[key] == null) process.env[key] = value;
  }
}

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = Number(err.status || err.statusCode) || 500;
  const code = status >= 400 && status < 500 ? status : 500;
  if (code >= 500) console.error(err);
  const message = code === 413
    ? 'Слишком большой запрос.'
    : code === 400
      ? 'Некорректное тело запроса.'
      : 'Не удалось обратиться к базе данных.';
  res.status(code).send(renderPage({
    title: 'Ошибка',
    body: `
      <h1>Ошибка</h1>
      <p class="muted">${escapeHtml(message)}</p>
      <a class="button" href="/register.html">Назад к форме</a>
    `,
  }));
});

prepareDatabase()
  .then(() => {
    const server = app.listen(PORT, () => {
      console.log(`Сервер запущен: http://localhost:${PORT}`);
      console.log(`База: ${process.env.PGDATABASE} на ${process.env.PGHOST}:${process.env.PGPORT}`);
    });
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`Порт ${PORT} уже занят.`);
      } else {
        console.error(err.message);
      }
      process.exit(1);
    });
  })
  .catch((err) => {
    console.error('Не удалось подключиться к PostgreSQL:', err.message);
    process.exit(1);
  });
