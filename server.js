// server.js
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");


const { getAddress, verifyMessage } = require("ethers");

dotenv.config();

const app = express();
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";

app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";


const nonceStore = new Map();
const NONCE_TTL_MS = 1000 * 60 * 5; 

function createNonceFor(address) {
  const nonce = `Sign this message to authenticate. Nonce: ${uuidv4()}`;
  nonceStore.set(address, { nonce, createdAt: Date.now() });
  return nonce;
}

function getNonceFor(address) {
  const rec = nonceStore.get(address);
  if (!rec) return null;
  if (Date.now() - rec.createdAt > NONCE_TTL_MS) {
    nonceStore.delete(address);
    return null;
  }
  return rec.nonce;
}


function normalizeAddress(addr) {
  try {
    return getAddress(addr);
  } catch (err) {
    return null;
  }
}


app.all("/api/nonce", (req, res) => {
  const address = req.method === "GET" ? req.query.address : req.body.address;
  if (!address) return res.status(400).json({ error: "address required" });

  const normalized = normalizeAddress(address);
  if (!normalized) return res.status(400).json({ error: "invalid address" });

  const nonce = createNonceFor(normalized);
  return res.json({ address: normalized, nonce });
});


app.post("/api/verify", async (req, res) => {
  const { address, signature } = req.body;
  if (!address || !signature) return res.status(400).json({ error: "address and signature required" });

  const normalized = normalizeAddress(address);
  if (!normalized) return res.status(400).json({ error: "invalid address" });

  const nonce = getNonceFor(normalized);
  if (!nonce) return res.status(400).json({ error: "nonce not found; request a new nonce" });

  try {
    const recovered = verifyMessage(nonce, signature);
    const recoveredNormalized = normalizeAddress(recovered);
    if (recoveredNormalized !== normalized) {
      return res.status(401).json({ error: "signature verification failed" });
    }

    const token = jwt.sign({ address: normalized }, JWT_SECRET, { expiresIn: "1h" });
    nonceStore.delete(normalized);
    return res.json({ success: true, token });
  } catch (err) {
    console.error("verify error:", err);
    return res.status(500).json({ error: "server error verifying signature" });
  }
});


app.get("/api/me", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "missing auth header" });

  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ error: "invalid auth header" });

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ authenticated: true, address: payload.address });
  } catch (err) {
    return res.status(401).json({ error: "invalid or expired token" });
  }
});


app.get("/api/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`);
  console.log(`CORS allowed origin: ${FRONTEND_ORIGIN}`);
});
