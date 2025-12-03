// Reset a user's password via Firebase Admin SDK
// Usage: node src/server/tools/resetPassword.js <email> <newPassword>

const admin = require('firebase-admin');

try {
  const serviceAccount = require('../serviceAccountKey.json');
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  }
} catch (e) {
  console.error('Failed to initialize Firebase Admin. Ensure serviceAccountKey.json exists.', e.message);
  process.exit(1);
}

const email = process.argv[2];
const newPassword = process.argv[3];

if (!email || !newPassword) {
  console.error('Usage: node src/server/tools/resetPassword.js <email> <newPassword>');
  process.exit(1);
}

async function run() {
  try {
    const user = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(user.uid, { password: newPassword });
    console.log(JSON.stringify({ success: true, uid: user.uid, email }, null, 2));
  } catch (err) {
    console.error('Failed to reset password:', err.message || err);
    process.exit(2);
  }
}

run();