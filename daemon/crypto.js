/**
 * Covalent Bond Cryptography Module
 *
 * End-to-end encryption between two peers through an untrusted relay.
 *
 * Design:
 *  - X25519 key agreement (raw 32-byte public keys)
 *  - The session code is NEVER sent to the relay. The relay routes by a
 *    routing ID derived from the code with PBKDF2, so the relay cannot
 *    recover the code from what it sees.
 *  - The session key binds BOTH the X25519 shared secret AND a key derived
 *    from the session code, plus a transcript hash of both public keys:
 *        sessionKey = HKDF(x25519Secret || codeKey, salt=transcriptHash)
 *    An active MITM relay that substitutes public keys still cannot derive
 *    the session key without the session code, and key confirmation fails.
 *  - Key confirmation: each peer proves knowledge of the session key with
 *    an HMAC tag over its role and the transcript before any transfer is
 *    allowed.
 *  - Messages are encrypted with AES-256-GCM under the session key.
 */

import crypto from 'crypto';
import { logger } from '../security/index.js';

const PBKDF2_ITERATIONS = 600000;      // OWASP guidance for PBKDF2-SHA256
const ROUTING_ITERATIONS = 100000;     // routing ID derivation (once per connect)
const X25519_KEY_BYTES = 32;

// DER prefixes for raw <-> DER conversion of X25519 keys
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

// ============================================================================
// X25519 Key Agreement
// ============================================================================

/**
 * Generate X25519 keypair for a session.
 * @returns {Object} { privateKey: Buffer(32), publicKey: Buffer(32) } raw keys
 */
export function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');

  const rawPublic = publicKey.export({ type: 'spki', format: 'der' }).subarray(-X25519_KEY_BYTES);
  const rawPrivate = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-X25519_KEY_BYTES);

  return { privateKey: Buffer.from(rawPrivate), publicKey: Buffer.from(rawPublic) };
}

function toBuffer(value, name) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string' && /^[0-9a-fA-F]+$/.test(value)) {
    return Buffer.from(value, 'hex');
  }
  throw new TypeError(`${name} must be a Buffer or hex string`);
}

/**
 * Validate a raw X25519 public key.
 * @throws {Error} If the key is malformed
 */
export function validatePublicKey(publicKey) {
  const pubKey = toBuffer(publicKey, 'publicKey');

  if (pubKey.length !== X25519_KEY_BYTES) {
    throw new Error(`Invalid public key length: ${pubKey.length} bytes (expected 32)`);
  }

  // All-zero public key would force a zero shared secret
  if (pubKey.every(b => b === 0)) {
    throw new Error('Invalid public key: all-zero key rejected');
  }

  return pubKey;
}

/**
 * Compute the X25519 shared secret.
 * @param {Buffer|string} myPrivateKey - Raw 32-byte private key (or hex)
 * @param {Buffer|string} theirPublicKey - Raw 32-byte public key (or hex)
 * @returns {Buffer} 32-byte shared secret
 */
export function deriveSharedSecret(myPrivateKey, theirPublicKey) {
  const rawPriv = toBuffer(myPrivateKey, 'privateKey');
  const rawPub = validatePublicKey(theirPublicKey);

  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, rawPriv]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, rawPub]),
    format: 'der',
    type: 'spki'
  });

  const secret = crypto.diffieHellman({ privateKey, publicKey });

  // RFC 7748: reject the all-zero shared secret (low-order point)
  if (secret.every(b => b === 0)) {
    throw new Error('Key agreement produced an all-zero secret; peer key rejected');
  }

  return secret;
}

// ============================================================================
// Session Code Derivations (code never leaves the local machine)
// ============================================================================

/**
 * Derive the relay routing ID from the session code.
 * This is the ONLY code-derived value the relay ever sees. PBKDF2 makes
 * offline recovery of the code from the routing ID impractical.
 * @param {string} sessionCode
 * @returns {string} 64-char hex routing ID
 */
export function deriveRoutingId(sessionCode) {
  return crypto.pbkdf2Sync(
    sessionCode,
    'CovalentBond-Routing',
    ROUTING_ITERATIONS,
    32,
    'sha256'
  ).toString('hex');
}

/**
 * Derive the code key: the session-code contribution to the session key.
 * Computed once per session (expensive by design).
 * @param {string} sessionCode
 * @returns {Buffer} 32-byte code key
 */
export function deriveCodeKey(sessionCode) {
  return crypto.pbkdf2Sync(
    sessionCode,
    'CovalentBond-CodeKey',
    PBKDF2_ITERATIONS,
    32,
    'sha256'
  );
}

/**
 * Transcript hash binds both public keys (host first) into key derivation,
 * so peers that saw different keys derive different session keys.
 * @param {Buffer|string} hostPublicKey
 * @param {Buffer|string} guestPublicKey
 * @returns {Buffer} 32-byte transcript hash
 */
export function transcriptHash(hostPublicKey, guestPublicKey) {
  return crypto.createHash('sha256')
    .update(toBuffer(hostPublicKey, 'hostPublicKey'))
    .update(toBuffer(guestPublicKey, 'guestPublicKey'))
    .digest();
}

/**
 * Derive the session key.
 * Requires BOTH the X25519 shared secret and the code key, bound to the
 * transcript of the exchanged public keys.
 * @param {Buffer} sharedSecret - X25519 shared secret
 * @param {Buffer} codeKey - From deriveCodeKey()
 * @param {Buffer} transcript - From transcriptHash()
 * @returns {Buffer} 32-byte AES-256 session key
 */
export function deriveSessionKey(sharedSecret, codeKey, transcript) {
  const ikm = Buffer.concat([sharedSecret, codeKey]);
  return Buffer.from(
    crypto.hkdfSync('sha256', ikm, transcript, 'CovalentBond-SessionKey', 32)
  );
}

// ============================================================================
// Key Confirmation
// ============================================================================

/**
 * Compute a key-confirmation tag proving knowledge of the session key.
 * @param {Buffer} sessionKey
 * @param {string} role - 'host' or 'guest'
 * @param {Buffer} transcript - From transcriptHash()
 * @returns {string} hex HMAC tag
 */
export function keyConfirmationTag(sessionKey, role, transcript) {
  if (role !== 'host' && role !== 'guest') {
    throw new Error(`Invalid role for key confirmation: ${role}`);
  }
  return crypto.createHmac('sha256', sessionKey)
    .update(`CovalentBond-Confirm|${role}|`)
    .update(transcript)
    .digest('hex');
}

/**
 * Verify a peer's key-confirmation tag in constant time.
 * @returns {boolean}
 */
export function verifyKeyConfirmation(sessionKey, peerRole, transcript, tag) {
  const expected = keyConfirmationTag(sessionKey, peerRole, transcript);
  const a = Buffer.from(expected, 'hex');
  let b;
  try {
    b = Buffer.from(tag, 'hex');
  } catch {
    return false;
  }
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ============================================================================
// Replay Attack Protection
// ============================================================================

/**
 * Generate cryptographic nonce for a message.
 * @returns {string} 32-character hex nonce
 */
export function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

const seenNonces = new Map(); // Map<nonce, timestamp>
const NONCE_EXPIRY_MS = 5 * 60 * 1000;

/**
 * Validate message nonce and timestamp to block replays.
 * @throws {Error} If validation fails
 */
export function validateNonceAndTimestamp(nonce, timestamp) {
  const now = Date.now();

  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) {
    throw new Error('Invalid message nonce');
  }

  if (typeof timestamp !== 'number' || Math.abs(now - timestamp) > NONCE_EXPIRY_MS) {
    throw new Error('Message timestamp too old or too far in future (possible replay attack)');
  }

  if (seenNonces.has(nonce)) {
    throw new Error('Duplicate nonce detected (replay attack blocked)');
  }

  seenNonces.set(nonce, timestamp);

  for (const [oldNonce, oldTimestamp] of seenNonces.entries()) {
    if (now - oldTimestamp > NONCE_EXPIRY_MS) {
      seenNonces.delete(oldNonce);
    }
  }
}

// ============================================================================
// AES-256-GCM Message Encryption (session key, derived once per session)
// ============================================================================

/**
 * Encrypt plaintext under the session key.
 * @param {string} plaintext
 * @param {Buffer|string} sessionKey - 32-byte session key (or hex)
 * @returns {Object} { v: 2, iv, encrypted, authTag } all hex
 */
export function encrypt(plaintext, sessionKey) {
  const key = toBuffer(sessionKey, 'sessionKey');
  if (key.length !== 32) {
    throw new Error('Session key must be 32 bytes');
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    v: 2,
    iv: iv.toString('hex'),
    encrypted,
    authTag: cipher.getAuthTag().toString('hex')
  };
}

/**
 * Decrypt ciphertext under the session key.
 * Throws if the auth tag does not verify (tampered or wrong key).
 * @param {Object} encryptedData - { iv, encrypted, authTag }
 * @param {Buffer|string} sessionKey - 32-byte session key (or hex)
 * @returns {string} plaintext
 */
export function decrypt(encryptedData, sessionKey) {
  const key = toBuffer(sessionKey, 'sessionKey');
  const { iv, encrypted, authTag } = encryptedData;

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Self-test: full handshake and message round-trip between two peers.
 * @returns {boolean}
 */
export function verifyCrypto() {
  try {
    const code = 'TEST-CODE-1234';
    const host = generateKeypair();
    const guest = generateKeypair();

    const codeKey = deriveCodeKey(code);
    const transcript = transcriptHash(host.publicKey, guest.publicKey);

    const hostKey = deriveSessionKey(
      deriveSharedSecret(host.privateKey, guest.publicKey), codeKey, transcript
    );
    const guestKey = deriveSessionKey(
      deriveSharedSecret(guest.privateKey, host.publicKey), codeKey, transcript
    );

    if (!hostKey.equals(guestKey)) return false;

    const tag = keyConfirmationTag(guestKey, 'guest', transcript);
    if (!verifyKeyConfirmation(hostKey, 'guest', transcript, tag)) return false;

    const encrypted = encrypt('Hello Covalent Bond', hostKey);
    return decrypt(encrypted, guestKey) === 'Hello Covalent Bond';
  } catch (error) {
    logger.error('Crypto verification failed:', error.message);
    return false;
  }
}
