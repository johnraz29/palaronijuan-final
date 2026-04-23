const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const dbPath = process.env.DATABASE_URL || path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

function initDb() {
  db.serialize(() => {
    // 1. USERS TABLE
    // Idinagdag ang name_change_count sa main structure
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      phone TEXT UNIQUE,
      password_hash TEXT,
      balance REAL DEFAULT 0,
      gcash_number TEXT,
      bank_account TEXT,
      name_change_count INTEGER DEFAULT 0,
      is_admin INTEGER DEFAULT 0,
      is_controller INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // 2. MIGRATIONS (Para sa mga existing na database)
    // Phone column
    db.run("ALTER TABLE users ADD COLUMN phone TEXT", (err) => {
       if (!err) {
         console.log("✅ Phone column added.");
         db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users (phone)");
       }
    });

    // GCash Number column
    db.run("ALTER TABLE users ADD COLUMN gcash_number TEXT", (err) => {
       if (!err) console.log("✅ GCash column added.");
    });

    // Bank Account column
    db.run("ALTER TABLE users ADD COLUMN bank_account TEXT", (err) => {
       if (!err) console.log("✅ Bank Account column added.");
    });

    // --- ITO ANG DAGDAG PARA SA NAME CHANGE LIMIT ---
    db.run("ALTER TABLE users ADD COLUMN name_change_count INTEGER DEFAULT 0", (err) => {
       if (!err) console.log("✅ Name Change Count column added.");
    });

    // 3. BETS
    db.run(`CREATE TABLE IF NOT EXISTS bets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      numbers TEXT,
      amount REAL,
      choice TEXT,
      game DEFAULT 'sabong',
      status TEXT DEFAULT 'pending',
      created_at TEXT
    )`);

    // 4. TRANSACTIONS
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      type TEXT,
      amount REAL,
      status TEXT,
      reference TEXT,
      created_at TEXT
    )`);

    // 5. RESULTS
    db.run(`CREATE TABLE IF NOT EXISTS results (
      id TEXT PRIMARY KEY,
      numbers TEXT,
      created_at TEXT
    )`);

    // 6. SETTINGS
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('live_stream_url', 'https://www.youtube.com/embed/live_stream_id')");
    db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('video_status', 'playing')");

    // 7. AUTO CREATE ADMIN
    db.get('SELECT id FROM users WHERE email=?', ['admin@lotto.com'], async (err, row) => {
      if (!row) {
        const hash = await bcrypt.hash('admin123', 10);
        db.run(
          'INSERT INTO users (name, email, phone, password_hash, is_admin) VALUES (?, ?, ?, ?, 1)',
          ['Super Admin', 'admin@lotto.com', '00000000000', hash]
        );
        console.log('✅ Admin created');
      }
    });

    // 8. AUTO CREATE CONTROLLER
    db.get('SELECT id FROM users WHERE email=?', ['controller@lotto.com'], async (err, row) => {
      if (!row) {
        const hash = await bcrypt.hash('123456', 10);
        db.run(
          'INSERT INTO users (name, email, phone, password_hash, is_controller) VALUES (?, ?, ?, ?, 1)',
          ['Controller', 'controller@lotto.com', '11111111111', hash]
        );
        console.log('✅ Controller created');
      }
    });
  });
}

module.exports = { initDb, db };