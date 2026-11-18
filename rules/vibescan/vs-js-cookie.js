// ruleid: vs-js-cookie
res.cookie("session", value);
// ok: vs-js-cookie
res.cookie("session", value, {httpOnly: true, secure: true, sameSite: "lax"});
