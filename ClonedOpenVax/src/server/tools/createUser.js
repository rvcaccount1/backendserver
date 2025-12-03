// Create a Firebase Auth user via Admin SDK and set Firestore role
// Usage:
//   node src/server/tools/createUser.js <email> <password> [role]
// Example:
//   node src/server/tools/createUser.js "chesca.saa@gmail.com" "P4ssword!" admin

const admin = require('firebase-admin');

// Initialize Firebase Admin using service account
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
const password = process.argv[3];
const role = (process.argv[4] || 'admin').trim();

if (!email || !password) {
  console.error('Usage: node src/server/tools/createUser.js <email> <password> [role]');
  process.exit(1);
}

async function ensureUser(email, password) {
  const db = admin.firestore();
  try {
    // Try creating a new user
    const newUser = await admin.auth().createUser({
      email,
      password,
      emailVerified: true,
      disabled: false,
    });

    // Set role document in Firestore
    await db.collection('users').doc(newUser.uid).set({
      email,
      role,
      isEmailVerified: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    return { created: true, uid: newUser.uid };
  } catch (err) {
    if (err && err.code === 'auth/email-already-exists') {
      // If user exists, fetch uid, reset password, and ensure role in Firestore
      const existing = await admin.auth().getUserByEmail(email);

      // Reset password and ensure verified/enabled in Auth
      await admin.auth().updateUser(existing.uid, {
        password,
        emailVerified: true,
        disabled: false,
      });

      // Ensure Firestore role and verification flags
      await db.collection('users').doc(existing.uid).set({
        email,
        role,
        isEmailVerified: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

      return { created: false, uid: existing.uid, passwordReset: true };
    }
    throw err;
  }
}

(async function run() {
  try {
    const result = await ensureUser(email.toLowerCase(), password);
    console.log(JSON.stringify({ success: true, ...result, email, role }, null, 2));
  } catch (error) {
    console.error('Failed to create or update user:', error.message || error);
    process.exit(2);
  }
})();