// Set a user's Firestore role
// Usage:
//   node src/server/tools/setUserRole.js <email|uid> <role>
// Examples:
//   node src/server/tools/setUserRole.js "user@example.com" superadmin
//   node src/server/tools/setUserRole.js NeQJCHmmh6ekrJfirnBhKSJCPox1 superadmin

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

const identifier = process.argv[2];
const role = (process.argv[3] || 'superadmin').trim();

if (!identifier || !role) {
  console.error('Usage: node src/server/tools/setUserRole.js <email|uid> <role>');
  process.exit(1);
}

async function resolveUid(idOrEmail) {
  if (idOrEmail.includes('@')) {
    const user = await admin.auth().getUserByEmail(idOrEmail);
    return user.uid;
  }
  return idOrEmail;
}

async function run() {
  try {
    const uid = await resolveUid(identifier);
    const db = admin.firestore();
    await db.collection('users').doc(uid).set({ role }, { merge: true });
    console.log(JSON.stringify({ success: true, uid, role }, null, 2));
  } catch (err) {
    console.error('Failed to set user role:', err.message || err);
    process.exit(2);
  }
}

run();