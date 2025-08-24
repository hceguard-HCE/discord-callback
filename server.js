// En lugar de /auth → cámbialo a /auth-url
app.get("/auth-url", (req, res) => {
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  res.send({
    url: `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
      REDIRECT_URI
    )}&response_type=code&scope=identify&code_challenge=${codeChallenge}&code_challenge_method=S256`,
    codeVerifier
  });
});

// Nuevo endpoint para que WinForms use
app.post("/token", express.json(), async (req, res) => {
  const { code, codeVerifier } = req.body;
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;

  const data = new URLSearchParams();
  data.append("client_id", CLIENT_ID);
  data.append("grant_type", "authorization_code");
  data.append("code", code);
  data.append("redirect_uri", REDIRECT_URI);
  data.append("code_verifier", codeVerifier);

  try {
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      body: data,
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });

    const tokenJson = await tokenResp.json();

    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });

    const user = await userResp.json();
    res.send(user); // devolvemos directamente los datos del usuario
  } catch (err) {
    res.send({ error: err.message });
  }
});
