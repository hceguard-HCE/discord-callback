import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID = process.env.CLIENT_ID; // Tu client_id de Discord
const CLIENT_SECRET = process.env.CLIENT_SECRET; // Tu client_secret
const REDIRECT_URI = process.env.REDIRECT_URI; // Ej: https://tu-app.onrender.com/callback

// Genera codeVerifier y codeChallenge
function base64URLEncode(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

app.get("/auth-url", (req, res) => {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(Buffer.from(codeVerifier)));

  const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  res.json({ url, codeVerifier });
});

app.post("/token", async (req, res) => {
  const { code, codeVerifier } = req.body;
  try {
    const params = new URLSearchParams();
    params.append("client_id", CLIENT_ID);
    params.append("client_secret", CLIENT_SECRET);
    params.append("grant_type", "authorization_code");
    params.append("code", code);
    params.append("redirect_uri", REDIRECT_URI);
    params.append("code_verifier", codeVerifier);

    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      body: params,
    });
    const tokenJson = await tokenResp.json();

    // Obtener info del usuario
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    const userJson = await userResp.json();

    // Devolver directamente a WinForms
    res.json({
      access_token: tokenJson.access_token,
      username: userJson.username,
      id: userJson.id,
      verified: userJson.verified,
      avatar: userJson.avatar,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
