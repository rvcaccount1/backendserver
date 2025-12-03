// Utility script to check if an admin account exists.
// Usage:
//   node src/server/tools/checkAdmin.js [email]
// If email is provided, checks existence of that user in Firebase Auth.
// Otherwise, checks Firestore for any user document with role === 'admin'.

const admin = require('firebase-admin');
const path = require('path');

// Initialize Admin SDK using the same service account as the server
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

async function run() {
  try {
    if (email) {
      try {
        const user = await admin.auth().getUserByEmail(email);
        console.log(JSON.stringify({ exists: true, uid: user.uid, email: user.email }, null, 2));
      } catch (err) {
        if (err && err.errorInfo && err.errorInfo.code === 'auth/user-not-found') {
          console.log(JSON.stringify({ exists: false, email }, null, 2));
        } else {
          console.error('Error checking user by email:', err.message || err);
          process.exit(2);
        }
      }
    } else {
      const db = admin.firestore();
      const snapshot = await db.collection('users').where('role', '==', 'admin').limit(1).get();
      if (!snapshot.empty) {
        const doc = snapshot.docs[0];
        const data = doc.data();
        console.log(JSON.stringify({ exists: true, uid: doc.id, email: data.email || null, fullName: data.fullName || null }, null, 2));
      } else {
        console.log(JSON.stringify({ exists: false }, null, 2));
      }
    }
  } catch (err) {
    console.error('Unexpected error:', err.message || err);
    process.exit(2);
  }
}

run();