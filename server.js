import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();
app.use(express.json());

const CLIENT_ID = process.env.CLIENT_ID;
const REDIRECT_URI = process.env.REDIRECT_URI;


const SCOPE = 'identify';

// Generar PKCE
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
    const hash = crypto.createHash('sha256').update(verifier).digest();
    return Buffer.from(hash).toString('base64url');
}

let currentVerifier = '';

app.get('/auth-url', (req, res) => {
    currentVerifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(currentVerifier);

    const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${SCOPE}&code_challenge=${challenge}&code_challenge_method=S256`;
    res.json({ url });
});

app.post('/exchange', async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'No code provided' });

    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: currentVerifier
    });

    try {
        const tokenResp = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: params
        });
        const tokenData = await tokenResp.json();

        if (tokenData.error) return res.status(400).json(tokenData);

        const userResp = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });

        const userData = await userResp.json();
        res.json(userData);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Servidor OAuth listo');
});
