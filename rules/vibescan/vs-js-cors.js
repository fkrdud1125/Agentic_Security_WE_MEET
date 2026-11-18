// ruleid: vs-js-cors
app.use(cors({origin: true, credentials: true}));
// ok: vs-js-cors
app.use(cors({origin: "https://example.invalid", credentials: true}));
