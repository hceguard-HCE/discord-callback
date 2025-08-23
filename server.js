import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.CLIENT_ID;
const REDIRECT_URI = process.env.REDIRECT_URI;

function base64URLEncode(str) {
    return Buffer.from(str).toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function sha256(buffer) {
    const crypto = await import('crypto');
    return crypto.subtle.digest('SHA-256', buffer);
}

// Ruta para generar URL de login
app.get("/login", (req, res) => {
    const codeVerifier = base64URLEncode(Buffer.from(Math.random().toString()));
    const codeChallenge = codeVerifier; // Para simplificar, usamos mismo valor (no recomendado para prod)
    const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify&code_challenge=${codeChallenge}&code_challenge_method=plain`;
    res.send(`<a href="${url}">Login con Discord</a>`);
});

// Callback que recibe el código
app.get("/callback", async (req, res) => {
    const code = req.query.code;
    if (!code) return res.send("No se recibió código");

    const params = new URLSearchParams();
    params.append("client_id", CLIENT_ID);
    params.append("grant_type", "authorization_code");
    params.append("code", code);
    params.append("redirect_uri", REDIRECT_URI);
    params.append("code_verifier", ""); // mismo que usaste en authorize
    // No estamos usando client_secret por ser app pública (PKCE)

    try {
        const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            body: params,
            headers: { "Content-Type": "application/x-www-form-urlencoded" }
        });

        const tokenData = await tokenResp.json();
        if (tokenData.error) return res.send(`Error: ${tokenData.error_description}`);

        const userResp = await fetch("https://discord.com/api/users/@me", {
            headers: { "Authorization": `Bearer ${tokenData.access_token}` }
        });
        const userData = await userResp.json();

        res.send(`<h2>Usuario Discord:</h2>
                  <p>Nombre: ${userData.username}</p>
                  <p>ID: ${userData.id}</p>
                  <p>Verificado: ${userData.verified}</p>
                  <img src="https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png" width="100"/>`);
    } catch (err) {
        res.send("Error: " + err.message);
    }
});

app.listen(PORT, () => console.log(`Servidor listo en puerto ${PORT}`));
