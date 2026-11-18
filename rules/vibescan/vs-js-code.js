const q = req.query.q;
// ruleid: vs-js-code
child_process.exec("ls " + q);
// ok: vs-js-code
child_process.execFile("ls", [q]);
