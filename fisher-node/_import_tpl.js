const Database = require('better-sqlite3');
const fs = require('fs');
const db = new Database('/opt/fisher-node/data/fisher.db');
const rows = JSON.parse(fs.readFileSync('/opt/fisher-node/inj_tpl.json', 'utf-8'));

db.exec("DROP TABLE IF EXISTS injection_templates");
db.exec(`CREATE TABLE injection_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  html_content TEXT NOT NULL,
  target_apps TEXT DEFAULT '[]',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
)`);

const cols = Object.keys(rows[0]);
const placeholders = cols.map(() => '?').join(',');
const insert = db.prepare(`INSERT INTO injection_templates (${cols.join(',')}) VALUES (${placeholders})`);
const tx = db.transaction((data) => {
  for (const r of data) {
    insert.run(...cols.map(c => r[c]));
  }
});
tx(rows);
fs.unlinkSync('/opt/fisher-node/inj_tpl.json');
console.log('OK:', rows.length);
