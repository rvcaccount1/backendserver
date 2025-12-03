// server.js
const express = require("express");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
const cors = require("cors");
const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Load .env variables from this server directory
// Ensures EMAIL_USER and EMAIL_PASS are read from src/server/.env
dotenv.config({ path: path.resolve(__dirname, ".env") });

const app = express();
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || null;
const allowedOriginsRaw = process.env.CORS_ORIGINS || '';
const allowedOrigins = allowedOriginsRaw.split(',').map((s) => s.trim()).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (process.env.CORS_ALLOW_ALL === 'true') return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json());

// 🔹 Initialize Firebase Admin SDK
const serviceAccountPath = path.resolve(__dirname, "serviceAccountKey.json");

if (fs.existsSync(serviceAccountPath)) {
  admin.initializeApp({
    credential: admin.credential.cert(require(serviceAccountPath)),
  });
  console.log("✅ Firebase Admin initialized.");
} else {
  console.error("❌ serviceAccountKey.json not found!");
}

let transporter = null;
try {
  const host = process.env.EMAIL_HOST;
  const user = (process.env.EMAIL_USER || '').trim();
  const pass = (process.env.EMAIL_PASS || '').trim();
  const port = process.env.EMAIL_PORT ? Number(process.env.EMAIL_PORT) : undefined;
  const secure = process.env.EMAIL_SECURE ? process.env.EMAIL_SECURE === 'true' : undefined;

  if (host && user && pass) {
    transporter = nodemailer.createTransport({
      host,
      port: port || 587,
      secure: secure ?? false,
      auth: { user, pass },
    });
  } else if (process.env.EMAIL_SERVICE && user && pass) {
    transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE,
      auth: { user, pass },
    });
  } else if (user && pass) {
    transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user, pass },
    });
  }
} catch (e) {
  try { console.error('Mailer setup error:', e?.message || e); } catch (_) {}
}
try { if (transporter) transporter.verify().then(() => console.log('Mailer ready')).catch((e) => console.error('Mailer error:', e?.message || e)); } catch (_) {}

function ensureTransporter() {
  if (transporter) return transporter;
  try {
    const host = process.env.EMAIL_HOST;
    const user = (process.env.EMAIL_USER || '').trim();
    const pass = (process.env.EMAIL_PASS || '').trim();
    const port = process.env.EMAIL_PORT ? Number(process.env.EMAIL_PORT) : undefined;
    const secure = process.env.EMAIL_SECURE ? process.env.EMAIL_SECURE === 'true' : undefined;
    if (host && user && pass) {
      transporter = nodemailer.createTransport({ host, port: port || 587, secure: secure ?? false, auth: { user, pass } });
    } else if (process.env.EMAIL_SERVICE && user && pass) {
      transporter = nodemailer.createTransport({ service: process.env.EMAIL_SERVICE, auth: { user, pass } });
    } else if (user && pass) {
      transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user, pass } });
    }
    try { if (transporter) transporter.verify().then(() => console.log('Mailer ready')).catch((e) => console.error('Mailer error:', e?.message || e)); } catch (_) {}
  } catch (e) {
    try { console.error('ensureTransporter error:', e?.message || e); } catch (_) {}
  }
  return transporter;
}

function getFrontendBase(req) {
  const envBase = (FRONTEND_BASE_URL || '').trim();
  if (envBase) return envBase.replace(/\/$/, '');
  const origin = (req.get('origin') || '').trim();
  if (origin) return origin.replace(/\/$/, '');
  const ref = (req.get('referer') || '').trim();
  if (ref) {
    try {
      const u = new URL(ref);
      return `${u.protocol}//${u.host}`.replace(/\/$/, '');
    } catch (_) {}
  }
  const hostBase = `${req.protocol}://${req.get('host')}`;
  return hostBase.replace(/\/$/, '');
}

// Helper: create signed token for email change
function createEmailChangeToken(payload, secret, ttlMs = 24 * 60 * 60 * 1000) {
  const issuedAt = Date.now();
  const expiresAt = issuedAt + ttlMs;
  const body = JSON.stringify({ ...payload, iat: issuedAt, exp: expiresAt });
  const signature = crypto.createHmac("sha256", secret).update(body).digest("hex");
  return Buffer.from(body).toString("base64url") + "." + signature;
}

function verifyEmailChangeToken(token, secret) {
  if (!token || token.indexOf(".") === -1) return null;
  const [bodyB64, signature] = token.split(".");
  try {
    const bodyJson = Buffer.from(bodyB64, "base64url").toString("utf8");
    const expected = crypto.createHmac("sha256", secret).update(bodyJson).digest("hex");
    if (expected !== signature) return null;
    const data = JSON.parse(bodyJson);
    if (Date.now() > Number(data.exp || 0)) return null;
    return data;
  } catch {
    return null;
  }
}

const EMAIL_CHANGE_SECRET = process.env.EMAIL_CHANGE_SECRET || "openvax-dev-secret";

async function getUserRole(uid) {
  const db = admin.firestore();
  const doc = await db.collection('users').doc(uid).get();
  return doc.exists ? (doc.data().role || null) : null;
}

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, message: 'Missing Authorization token' });
    const decoded = await admin.auth().verifyIdToken(token);
    const role = await getUserRole(decoded.uid);
    req.auth = { uid: decoded.uid, email: decoded.email || null, role };
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Invalid Authorization token' });
  }
}

function requireRole(role) {
  return function (req, res, next) {
    const r = (req.auth && req.auth.role) || null;
    if (r !== role) return res.status(403).json({ success: false, message: 'Forbidden' });
    next();
  };
}

// Request email change: send verification email with CTA
app.post("/employee/request-email-change", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, message: "Missing Authorization token" });
    const decoded = await admin.auth().verifyIdToken(token);
    const { newEmail } = req.body || {};
    if (!newEmail) return res.status(400).json({ success: false, message: "New email is required" });

    // Create signed verification token
    const changeToken = createEmailChangeToken({ uid: decoded.uid, newEmail }, EMAIL_CHANGE_SECRET, 48 * 60 * 60 * 1000);

    // Compose aesthetic email HTML
    const verifyUrl = `${req.protocol}://${req.get("host")}/employee/verify-email-change?token=${encodeURIComponent(changeToken)}`;
    const html = `
      <div style="font-family: 'Poppins', Arial, sans-serif; background-color:#f6f9fc; padding:24px;">
        <table align="center" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.06); overflow:hidden;">
          <tr>
            <td style="background:#003087; padding:24px;"></td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h2 style="color:#0f172a; margin:0 0 8px;">Verify Your Email Change</h2>
              <p style="color:#334155; margin:0 0 16px;">You requested to change your account email for OpenVax. For your security, please verify this change by clicking the button below.</p>
              <div style="text-align:center; margin:28px 0;">
                <a href="${verifyUrl}" style="display:inline-block; background:#0ea5e9; color:#ffffff; text-decoration:none; padding:14px 24px; border-radius:999px; font-weight:600;">Verify Change Email</a>
              </div>
              <p style="color:#64748b; font-size:14px;">If you did not request this change, please ignore this email. Your current email will remain unchanged.</p>
              
            </td>
          </tr>
          <tr>
            <td style="background:#f8fafc; color:#64748b; font-size:12px; padding:16px; text-align:center;">© ${new Date().getFullYear()} OpenVax. All rights reserved.</td>
          </tr>
        </table>
      </div>
    `;

    const t2 = ensureTransporter();
    if (!t2 || typeof t2.sendMail !== 'function') return res.status(500).json({ success: false, message: 'Email sending not configured on server' });
    await t2.sendMail({
      from: process.env.EMAIL_FROM || `"OpenVax" <${process.env.EMAIL_USER}>`,
      to: newEmail,
      subject: "OpenVax: Verify your email change",
      html
    });

    return res.json({ success: true, message: "Verification email sent" });
  } catch (err) {
    const msg = err?.message || "Failed to send verification email";
    return res.status(500).json({ success: false, message: msg });
  }
});

// Complete email change from verification link
app.get("/employee/verify-email-change", async (req, res) => {
  try {
    const { token } = req.query;
    const data = verifyEmailChangeToken(token, EMAIL_CHANGE_SECRET);
    if (!data) {
      return res.status(400).send("<h1>Invalid or expired link</h1>");
    }
    const { uid, newEmail } = data;
    // Update in Auth and Firestore
    try {
      await admin.auth().updateUser(uid, { email: newEmail, emailVerified: true });
    } catch (err) {
      const code = err?.errorInfo?.code || err?.code || "unknown";
      if (code === "auth/email-already-exists") {
        const msg = `
          <div style="font-family: Poppins, Arial, sans-serif; background:#f6f9fc; min-height:100vh; display:flex; align-items:center; justify-content:center;">
            <div style="background:#ffffff; border-radius:16px; padding:32px; box-shadow:0 10px 30px rgba(0,0,0,0.06); max-width:560px; text-align:center;">
              <h2 style="color:#0f172a; margin:0 0 8px;">Email Already In Use</h2>
              <p style="color:#334155; margin:0 0 16px;">We couldn’t complete the change because <strong>${newEmail}</strong> is already associated with another OpenVax account.</p>
              <a href="${getFrontendBase(req)}/employee/profile" style="display:inline-block; background:#003087; color:#fff; text-decoration:none; padding:12px 20px; border-radius:999px; font-weight:600;">Back to Profile</a>
            </div>
          </div>`;
        return res.status(409).send(msg);
      }
      const generic = `
        <div style="font-family: Poppins, Arial, sans-serif; background:#f6f9fc; min-height:100vh; display:flex; align-items:center; justify-content:center;">
          <div style="background:#ffffff; border-radius:16px; padding:32px; box-shadow:0 10px 30px rgba(0,0,0,0.06); max-width:560px; text-align:center;">
            <h2 style="color:#0f172a; margin:0 0 8px;">Unable to Complete</h2>
            <p style="color:#334155; margin:0 0 16px;">Something went wrong completing your email change. Please retry from the profile page.</p>
            <code style="display:block; color:#64748b; font-size:12px; margin-bottom:16px;">${code}</code>
            <a href="${getFrontendBase(req)}/employee/profile" style="display:inline-block; background:#003087; color:#fff; text-decoration:none; padding:12px 20px; border-radius:999px; font-weight:600;">Back to Profile</a>
          </div>
        </div>`;
      return res.status(500).send(generic);
    }
    const db = admin.firestore();
    await db.collection("users").doc(uid).set({ email: newEmail, isEmailVerified: true, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

    const html = `
      <div style="font-family: Poppins, Arial, sans-serif; background:#f6f9fc; min-height:100vh; display:flex; align-items:center; justify-content:center;">
        <div style="background:#ffffff; border-radius:16px; padding:32px; box-shadow:0 10px 30px rgba(0,0,0,0.06); max-width:560px; text-align:center;">
          <h2 style="color:#0f172a; margin:0 0 8px;">Email Change Verified</h2>
          <p style="color:#334155; margin:0 0 16px;">Your account email has been updated to <strong>${newEmail}</strong>.</p>
          <p style="color:#64748b; font-size:14px; margin:8px 0 0;">Your email change has been saved, due to privacy policy you will be automatically logged out.</p>
        </div>
      </div>
      <script>
        setTimeout(function(){ try { window.close(); } catch(e){} }, 1500);
      </script>`;
    res.status(200).send(html);
  } catch (err) {
    console.error("verify-email-change failed:", err?.message || err);
    res.status(500).send("<h1>Something went wrong completing email change</h1>");
  }
});

// ================= ROUTES ================= //
// Force password change (OTP-based reset)
app.post('/api/force-password-change', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required.' });
  }
  try {
    // Find user by email
    const userRecord = await admin.auth().getUserByEmail(email);
    // Update password to OTP
    await admin.auth().updateUser(userRecord.uid, { password: otp });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Test route
app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

// Send OTP
// Send OTP
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required" });
  }

  try {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    const emailKey = encodeURIComponent(email); // safer Firestore ID

    // Find user by email and set password to OTP
    try {
      const userRecord = await admin.auth().getUserByEmail(email);
      await admin.auth().updateUser(userRecord.uid, { password: otp });
    } catch (err) {
      // If user not found, don't set password, but still send OTP for verification flow
      console.error('User not found or error updating password:', err.message);
    }

    await admin.firestore().collection("otps").doc(emailKey).set({
      otp,
      createdAt: new Date(),
      expiresAt,
    });

    const html = `
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet" />
          <title>OpenVax Email Verification</title>
          <style>
            .root { background:#ffffff; font-family:'Poppins', Arial, sans-serif; color:#1d1c1d; }
            .container { max-width:600px; margin:0 auto; padding:0 20px; }
            .brandWrap { margin-top:28px; }
            .brandLogo { width:140px; height:auto; display:block; }
            .heading { font-size:28px; font-weight:700; line-height:1.3; margin:30px 0 10px; color:#1d1c1d; }
            .text { font-size:16px; color:#1d1c1d; margin:0 0 24px; }
            .codeBox { background:#f5f4f5; border-radius:12px; margin:24px 0; padding:20px; text-align:center; }
            .code { font-size:32px; font-weight:600; letter-spacing:2px; color:#1d1c1d; }
            .note { font-size:13px; color:#6b7280; margin:10px 0 28px; }
          </style>
        </head>
        <body class="root">
          <div class="container">
            <div class="brandWrap">
              <img src="cid:ovxlogo" alt="OpenVax" class="brandLogo" />
            </div>
            <h1 class="heading">Confirm your email address</h1>
            <p class="text">Your confirmation code is below — enter it in your open OpenVax window and we'll help you get signed in.</p>
            <div class="codeBox">
              <div class="code">${otp}</div>
            </div>
            <p class="note">If you didn't request this email, you can safely ignore it.</p>
          </div>
        </body>
      </html>
    `;

    // Attach logo if available. Resolve path relative to `src/server` -> `src/assets/images`.
    const logoPath = path.resolve(__dirname, '../assets/images/OpenVax-Logo-Final-White.png');
    const mailAttachments = [];
    try {
      if (fs.existsSync(logoPath)) {
        mailAttachments.push({ filename: 'openvax-logo.png', path: logoPath, cid: 'ovxlogo' });
      } else {
        console.warn('[send-otp] logo not found at', logoPath, '- sending email without attachment');
      }
    } catch (fsErr) {
      console.warn('[send-otp] error checking logo path', fsErr?.message || fsErr);
    }

    const t = ensureTransporter();
    try { console.log('[send-otp] transporter:', !!t); } catch (_) {}
    if (!t || typeof t.sendMail !== 'function') {
      return res.status(500).json({ success: false, message: 'Email sending not configured on server' });
    }

    await t.sendMail({
      from: `"OpenVax" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "OpenVax Email Verification Code",
      text: `Your OTP code is: ${otp}. It will expire in 5 minutes.`,
      html,
      attachments: mailAttachments
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    console.error("❌ Error sending OTP:", error);
    res.status(500).json({ success: false, message: error.message || "Failed to send OTP" });
  }
});

// Admin-only: Create another admin account
app.post("/admin/create-admin", requireAuth, requireRole('admin'), async (req, res) => {
  const { email, password, fullName, lastName, firstName, middleName } = req.body || {};

  try {
    const db = admin.firestore();

    let uid = null;
    const emailLower = (email || "").toLowerCase();
    const passwordRaw = (() => {
      const p = (password || "").toString();
      if (p) return p;
      const bday = (req.body?.birthday || '').toString();
      try {
        if (bday) {
          const d = new Date(bday);
          if (!Number.isNaN(d.getTime())) {
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            const yyyy = String(d.getFullYear());
            return `${mm}${dd}${yyyy}`; // match frontend convention
          }
        }
      } catch (_) {}
      // Fallback strong random password
      return Math.random().toString(36).slice(-10) + "Aa1!";
    })();
    if (!emailLower) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }
    let newUser;
    try {
      newUser = await admin.auth().createUser({
        email: emailLower,
        password: passwordRaw,
        emailVerified: true,
        disabled: false,
      });
      uid = newUser.uid;
    } catch (err) {
      if (err?.code === 'auth/email-already-exists') {
        const existing = await admin.auth().getUserByEmail(emailLower);
        uid = existing.uid;
        await admin.auth().updateUser(uid, {
          password: passwordRaw,
          emailVerified: true,
          disabled: false,
        });
      } else {
        throw err;
      }
    }

    // Double-check the user exists in Auth
    await admin.auth().getUser(uid);

    // Normalize provided name fields, gracefully parse from fullName when parts are missing
    const trim = (s) => (s || "").trim();
    const provided = { lastName: trim(lastName), firstName: trim(firstName), middleName: trim(middleName) };
    let parsed = { ...provided };

    if ((!provided.lastName || !provided.firstName) && fullName && trim(fullName)) {
      const f = trim(fullName);
      if (f.includes(",")) {
        const [ln, restRaw] = f.split(",").map((x) => x.trim());
        const rest = restRaw.split(/\s+/).filter(Boolean);
        parsed.lastName = provided.lastName || ln;
        parsed.firstName = provided.firstName || (rest[0] || "");
        parsed.middleName = provided.middleName || (rest.slice(1).join(" ") || "");
      } else {
        const parts = f.split(/\s+/).filter(Boolean);
        const ln = parts.length ? parts[parts.length - 1] : "";
        const fn = parts.length ? parts[0] : "";
        const mn = parts.length > 2 ? parts.slice(1, -1).join(" ") : (parts.length === 2 ? "" : "");
        parsed.lastName = provided.lastName || ln;
        parsed.firstName = provided.firstName || fn;
        parsed.middleName = provided.middleName || mn;
      }
    }

    const composedFullName =
      trim(fullName) ||
      (parsed.lastName && parsed.firstName
        ? `${parsed.lastName}, ${parsed.firstName}${parsed.middleName ? ` ${parsed.middleName}` : ""}`
        : "");

    // Merge any additional, non-reserved fields from request for dynamic profile support
    const reservedKeys = new Set([
      'email','password','fullName','lastName','firstName','middleName',
      'role','isEmailVerified','createdAt','uid'
    ]);
    const additionalFieldsRaw = { ...(req.body || {}) };
    for (const key of reservedKeys) delete additionalFieldsRaw[key];

    // Determine requested role; default to 'employee' if not provided
    const requestedRoleRaw = (req.body?.role || '').toString().trim().toLowerCase();
    const requestedRole = ['admin', 'employee'].includes(requestedRoleRaw) ? requestedRoleRaw : 'employee';

    // Persist admin/employee profile in Firestore with name parts
    await db.collection("users").doc(uid).set({
      ...additionalFieldsRaw,
      lastName: parsed.lastName || "",
      firstName: parsed.firstName || "",
      middleName: parsed.middleName || "",
      fullName: composedFullName,
      email: emailLower,
      role: requestedRole,
      isEmailVerified: true,
      isActive: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    try {
      const logoPath = path.resolve(__dirname, '../assets/images/OpenVax-Logo-Final-White.png');
      const mailAttachments = [];
      try {
        if (fs.existsSync(logoPath)) {
          mailAttachments.push({ filename: 'openvax-logo.png', path: logoPath, cid: 'ovxlogo' });
        }
      } catch (_) {}
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>OpenVax Account Created</title>
            <style>
              body{font-family: 'Poppins', Arial, sans-serif; background:#f6f9fc; margin:0; padding:24px;}
              .card{max-width:560px; margin:0 auto; background:#ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.06); overflow:hidden;}
              .header{background:#003087; padding:24px; color:#fff; text-align:center;}
              .content{padding:32px; color:#334155;}
              .title{color:#0f172a; margin:0 0 8px;}
              .note{color:#64748b; font-size:14px;}
            </style>
          </head>
          <body>
            <div class="card">
              <div class="header">OpenVax</div>
              <div class="content">
                <h2 class="title">Your Account Is Ready</h2>
                <p>Welcome to OpenVax. An administrator has created your account.</p>
                <p><strong>Email:</strong> ${emailLower}</p>
                <p><strong>Temporary Password:</strong> ${passwordRaw}</p>
                <p class="note">Your temporary password follows your birthday format MMDDYYYY if provided. Please sign in and change your password immediately.</p>
              </div>
            </div>
          </body>
        </html>
      `;
      const t3 = ensureTransporter();
      if (!t3 || typeof t3.sendMail !== 'function') return res.status(500).json({ success: false, message: 'Email sending not configured on server' });
      await t3.sendMail({
        from: `"OpenVax" <${process.env.EMAIL_USER}>`,
        to: emailLower,
        subject: 'OpenVax Account Created',
        text: `Your OpenVax account has been created. Email: ${emailLower} Temporary Password: ${passwordRaw}. Please sign in and change your password.`,
        html,
        attachments: mailAttachments
      });
      try { console.log('Account email sent to', emailLower); } catch (_) {}
    } catch (mailErr) {
      console.error('Error sending account email:', mailErr?.message || mailErr);
    }

    return res.json({ success: true, uid, message: "User created" });
  } catch (error) {
    console.error("❌ Error creating admin:", error);
    // Handle common errors from Admin SDK
    const message = error?.message || "Failed to create admin";
    return res.status(500).json({ success: false, message });
  }
});

// Admin-only: Ensure a Firebase Auth user exists for a given email
app.post('/admin/ensure-auth-user', requireAuth, requireRole('admin'), async (req, res) => {
  const { email, password, birthday } = req.body || {};
  if (!email) return res.status(400).json({ success: false, message: 'Email is required' });

  try {
    const emailLower = (email || '').toLowerCase();
    const passwordRaw = (() => {
      const p = (password || '').toString();
      if (p) return p;
      const b = (birthday || '').toString();
      try {
        if (b) {
          const d = new Date(b);
          if (!Number.isNaN(d.getTime())) {
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            const yyyy = String(d.getFullYear());
            return `${mm}${dd}${yyyy}`;
          }
        }
      } catch (_) {}
      return Math.random().toString(36).slice(-10) + 'Aa1!';
    })();

    let uid;
    try {
      const created = await admin.auth().createUser({
        email: emailLower,
        password: passwordRaw,
        emailVerified: true,
        disabled: false,
      });
      uid = created.uid;
    } catch (err) {
      if (err?.code === 'auth/email-already-exists') {
        const existing = await admin.auth().getUserByEmail(emailLower);
        uid = existing.uid;
        await admin.auth().updateUser(uid, { password: passwordRaw, emailVerified: true, disabled: false });
      } else {
        throw err;
      }
    }

    await admin.auth().getUser(uid);
    return res.json({ success: true, uid });
  } catch (error) {
    console.error('❌ ensure-auth-user error:', error);
    return res.status(500).json({ success: false, message: error?.message || 'Failed to ensure auth user' });
  }
});

// Admin-only: Delete an admin account (removes from Auth and Firestore)
app.post('/admin/delete-admin', requireAuth, requireRole('admin'), async (req, res) => {
  const { uid } = req.body || {};
  if (!uid) {
    return res.status(400).json({ success: false, message: 'Missing uid to delete' });
  }

  try {
    const db = admin.firestore();

    // Delete user from Auth. If the uid does not correspond to an Auth user
    // attempt to recover by looking up the Firestore document's email and
    // deleting the Auth user by email. If still not found, proceed to remove
    // the Firestore profile and return success (we consider the profile deleted).
    try {
      await admin.auth().deleteUser(uid);
    } catch (authErr) {
      console.warn('[delete-admin] deleteUser failed for uid', uid, authErr.message || authErr);
      // Try to read Firestore doc to find an email to delete by
      try {
        const userDocSnap = await db.collection('users').doc(uid).get();
        if (userDocSnap.exists) {
          const userEmail = userDocSnap.data()?.email;
          if (userEmail) {
            try {
              const userRecord = await admin.auth().getUserByEmail(userEmail);
              await admin.auth().deleteUser(userRecord.uid);
            } catch (byEmailErr) {
              console.warn('[delete-admin] delete by email failed for', userEmail, byEmailErr.message || byEmailErr);
            }
          }
        }
      } catch (lookupErr) {
        console.warn('[delete-admin] failed to lookup Firestore user doc', lookupErr.message || lookupErr);
      }
    }

    // Remove user profile from Firestore (if exists)
    await db.collection('users').doc(uid).delete().catch(() => null);

    return res.json({ success: true, message: 'Admin account deleted' });
  } catch (error) {
    console.error('❌ Error deleting admin:', error);
    const message = error?.message || 'Failed to delete admin';
    return res.status(500).json({ success: false, message });
  }
});

// Admin-only: Archive/unarchive an admin account
app.post('/admin/archive-admin', requireAuth, requireRole('admin'), async (req, res) => {
  const { uid, disable } = req.body || {};
  if (!uid || typeof disable === 'undefined') return res.status(400).json({ success: false, message: 'Missing uid or disable flag' });

  try {
    const db = admin.firestore();

    // Disable/enable in Firebase Auth. If the Auth user cannot be found,
    // log and continue because Firestore may already contain the profile
    // (some legacy accounts use different doc ids). Do not fail the whole
    // request for a missing Auth user.
    try {
      await admin.auth().updateUser(uid, { disabled: !!disable });
    } catch (authUpdateErr) {
      console.warn('[archive-admin] updateUser failed for uid', uid, authUpdateErr.message || authUpdateErr);
      // Attempt to resolve by email stored in Firestore (non-fatal)
      try {
        const maybeUserDoc = await db.collection('users').doc(uid).get();
        if (maybeUserDoc.exists) {
          const maybeEmail = maybeUserDoc.data()?.email;
          if (maybeEmail) {
            try {
              const userRec = await admin.auth().getUserByEmail(maybeEmail);
              await admin.auth().updateUser(userRec.uid, { disabled: !!disable });
            } catch (byEmailErr) {
              console.warn('[archive-admin] update by email failed for', maybeEmail, byEmailErr.message || byEmailErr);
            }
          }
        }
      } catch (lookupErr) {
        console.warn('[archive-admin] failed to lookup Firestore user doc', lookupErr.message || lookupErr);
      }
    }

    // Update Firestore user doc isActive flag
    const userRef = await db.collection('users').doc(uid).get();
    const userEmail = userRef.data()?.email;

    await db.collection('users').doc(uid).set({ isActive: !disable }, { merge: true });

    // Archive/unarchive related vaccine stock documents by matching email
    if (userEmail) {
      try {
        const vaccineStockDocs = await db.collection('vaccineStock')
          .where('createdBy.email', '==', userEmail)
          .get();

        if (!vaccineStockDocs.empty) {
          const batch = db.batch();
          const timestamp = admin.firestore.FieldValue.serverTimestamp();

          vaccineStockDocs.forEach((doc) => {
            const docRef = db.collection('vaccineStock').doc(doc.id);

            if (disable) {
              // Archiving: set isArchived to true
              batch.update(docRef, {
                isArchived: true,
                archivedAt: timestamp,
                archivedBy: requesterEmail
              });
            } else {
              // Unarchiving: set isArchived to false
              batch.update(docRef, {
                isArchived: false,
                archivedAt: admin.firestore.FieldValue.delete(),
                archivedBy: admin.firestore.FieldValue.delete()
              });
            }
          });

          await batch.commit();
        }
      } catch (vsError) {
        // Don't fail the entire request if vaccine stock update fails
      }
    } else {
      console.log(`[Archive Admin] No email found for user ${uid}`);
    }

    return res.json({ success: true, message: disable ? 'Admin archived' : 'Admin unarchived' });
  } catch (error) {
    console.error('❌ Error archiving admin:', error);
    return res.status(500).json({ success: false, message: error?.message || 'Failed to archive admin' });
  }
});


// Verify OTP
// Verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: "Email and OTP are required" });
  }

  try {
    const emailKey = encodeURIComponent(email);
    const docRef = admin.firestore().collection("otps").doc(emailKey);
    const docSnap = await docRef.get();

    if (!docSnap.exists) {
      return res.status(400).json({ success: false, message: "No OTP found for this email" });
    }

    const data = docSnap.data();

    if (data.expiresAt && Date.now() > data.expiresAt) {
      await docRef.delete(); // cleanup expired OTP
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    if (data.otp === otp) {
      await docRef.delete();
      return res.json({ success: true, message: "OTP verified successfully" });
    } else {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
  } catch (error) {
    console.error("❌ Error verifying OTP:", error);
    res.status(500).json({ success: false, message: error.message || "Failed to verify OTP" });
  }
});


// ================= START SERVER ================= //
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
