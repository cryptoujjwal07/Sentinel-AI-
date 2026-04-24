/**
 * Firebase Admin SDK Configuration
 * Used for verifying Google Sign-In ID tokens on the backend
 */

const admin = require('firebase-admin');

// Initialize Firebase Admin with project ID only (no service account needed for token verification)
if (!admin.apps.length) {
  admin.initializeApp({
    projectId: process.env.FIREBASE_PROJECT_ID,
  });
}

/**
 * Verify a Firebase ID token and return the decoded user info
 * @param {string} idToken - The Firebase ID token from the client
 * @returns {Promise<object>} Decoded token with uid, email, name, picture, etc.
 */
const verifyGoogleToken = async (idToken) => {
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    return decodedToken;
  } catch (error) {
    console.error('[FirebaseAdmin] Token verification failed:', error.message);
    throw new Error('Invalid or expired Google token');
  }
};

module.exports = { verifyGoogleToken };
