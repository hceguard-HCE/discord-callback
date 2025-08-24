import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express(); // ✅ Definición de app
const port = process.env.PORT || 5000;

// Middleware para JSON
app.use(express.json());

// CORS simple
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// Funciones PKCE
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

// Guardar codeVerifier temporalmente (en memoria)
const sessions = new Map();

// Endpoint para iniciar OAuth
app.get("/auth-url", (req, res) => {
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Generar state único para seguridad
  const state = crypto.randomBytes(16).toString("hex");
  sessions.set(state, codeVerifier);

  const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&response_type=code&scope=identify&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;

  res.send({ url, codeVerifier: codeVerifier, state });
});

// Endpoint para intercambiar code por token y obtener usuario
app.post("/token", async (req, res) => {
  const { code, codeVerifier, state } = req.body;

  if (!code || !codeVerifier || !state) {
    return res.status(400).send({ error: "Faltan parámetros" });
  }

  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;

  try {
    // Intercambio de code por token
    const data = new URLSearchParams();
    data.append("client_id", CLIENT_ID);
    data.append("grant_type", "authorization_code");
    data.append("code", code);
    data.append("redirect_uri", REDIRECT_URI);
    data.append("code_verifier", codeVerifier);

    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      body: data,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const tokenJson = await tokenResp.json();

    if (!tokenJson.access_token) {
      return res.status(400).send({ error: "No se pudo obtener access_token", details: tokenJson });
    }

    // Obtener datos del usuario
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });

    const user = await userResp.json();

    res.send(user);
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en puerto ${port}`);
});
