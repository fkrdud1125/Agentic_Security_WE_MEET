// Inert synthetic fixtures, not a runnable application.
// GT: P26 CI-05 vulnerable
const STRIPE_SECRET = 'sk_live_ABCDEFGHIJKLMNOP01234567';
// GT: P27 CI-05 vulnerable
const apiKey = 'AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ012345678';
app.get('/notes', (req, res) => {
  const q = req.query.q;
  // GT: P28 CI-02 vulnerable
  db.query('SELECT * FROM notes WHERE id=' + q);
  // GT: P29 CI-06 vulnerable
  res.send('<p>' + q);
  // GT: P30 CI-01 vulnerable
  child_process.exec('ls ' + q);
  // GT: S16 CI-02 safe
  db.query('SELECT * FROM notes WHERE id=?', [q]);
  // GT: S17 CI-06 safe
  res.json({value: q});
  // GT: S18 CI-01 safe
  child_process.execFile('ls', [q]);
});
// GT: P31 CI-06 vulnerable
const view = <div dangerouslySetInnerHTML={{__html: value}} />;
// GT: P32 CI-06 vulnerable
document.body.innerHTML = location.hash;
// GT: P33 CI-05 vulnerable
const client = createClient(url, 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.synthetic_signature');
// GT: S19 CI-06 safe
const safeView = <div>{value}</div>;
// GT: S20 CI-06 safe
document.body.textContent = location.hash;
// GT: S21 CI-05 safe
const apiKeyExample = 'your-api-key';
