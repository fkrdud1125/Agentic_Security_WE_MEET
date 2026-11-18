const q = req.query.q;
// ruleid: vs-js-path
res.sendFile(q);
// ok: vs-js-path
res.sendFile("/public/help.html");
