const q = req.query.q;
// ruleid: vs-js-sql
db.query(`SELECT * FROM notes WHERE id=${q}`);
// ok: vs-js-sql
db.query("SELECT * FROM notes WHERE id=?", [q]);
