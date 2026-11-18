// ruleid: vs-js-error
res.send(err.stack);
// ok: vs-js-error
res.status(500).send("Request failed");
