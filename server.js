import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
const port = process.env.PORT || 5000;

// Configuración de CORS si lo necesitas
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// Función para generar code verifier y challenge
function base64UrlEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateCodeVerifier() {
  const randomBytes = crypto.randomBytes(32);
  return base64UrlEncode(randomBytes);
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64UrlEncode(hash);
}

// Ruta principal de OAuth2
app.get("/auth", (req, res) => {
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI; // poner https://tu-app.onrender.com/callback
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Guardar codeVerifier en memoria o DB según tu lógica
  // Por simplicidad, aquí lo retornamos
  res.send({
    url: `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&code_challenge=${codeChallenge}&code_challenge_method=S256`,
    codeVerifier
  });
});

// Callback de Discord
app.get("/callback", async (req, res) => {
  const code = req.query.code;
  const CLIENT_ID = process.env.CLIENT_ID;
  const REDIRECT_URI = process.env.REDIRECT_URI;
  const codeVerifier = req.query.code_verifier; // si lo guardaste en memoria/DB, recupéralo

  if (!code) {
    return res.send("No se recibió código de autorización");
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
    res.send(tokenJson); // muestra access_token, refresh_token, etc.
  } catch (err) {
    res.send({ error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en puerto ${port}`);
});
