const q = req.query.q;
// ruleid: vs-js-xss
res.send("<p>" + q);
// ok: vs-js-xss
res.json({value: q});
