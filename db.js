const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'games.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    subcategory TEXT,
    platform TEXT,
    version TEXT,
    size_bytes INTEGER,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    downloads INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_games_category ON games(category);
  CREATE INDEX IF NOT EXISTS idx_games_title ON games(title);
`);

const cols = db.prepare("PRAGMA table_info(games)").all().map(c => c.name);
if (!cols.includes('category')) db.exec("ALTER TABLE games ADD COLUMN category TEXT");
if (!cols.includes('subcategory')) db.exec("ALTER TABLE games ADD COLUMN subcategory TEXT");

module.exports = db;
