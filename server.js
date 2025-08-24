import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
const port = process.env.PORT || 5000;

const sessions = new Map(); // almacenar code_verifier con state

function base64UrlEncode(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generateCodeVerifier() {
  const randomBytes = crypto.randomBytes(32);
  return base64UrlEncode(randomBytes);
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64UrlEncode(hash);
}

// Ruta para iniciar OAuth
app.get("/auth", (req, res) => {
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString("hex");

  // Guardamos el codeVerifier usando el state
  sessions.set(state, codeVerifier);

  res.send({
    url: `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
      REDIRECT_URI
    )}&response_type=code&scope=identify%20email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`
  });
});

// Callback de Discord
app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;

  if (!code || !state) {
    return res.status(400).send("Falta code o state");
  }

  const codeVerifier = sessions.get(state);
  if (!codeVerifier) {
    return res.status(400).send("State inválido o expirado");
  }

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

    // Obtener datos del usuario
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const user = await userResp.json();

    res.send({ tokens: tokenJson, user });
  } catch (err) {
    res.send({ error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en puerto ${port}`);
});
