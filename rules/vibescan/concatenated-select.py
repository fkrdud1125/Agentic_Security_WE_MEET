query = "select * from notes where id=" + x + ";"
# ruleid: concatenated-select
db.execute(query)
# ok: concatenated-select
db.execute("select * from notes where id=?", (x,))
