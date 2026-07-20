/**
 * Covalent Bond Session Manager
 * Handles session creation and key exchange state.
 *
 * The relay only ever sees the routing ID, never the session code.
 * Session state is memory-only: the session code, private keys, and the
 * derived session key never touch disk. Sessions are ephemeral by design;
 * a process restart ends them (the relay-side peer ID changes on restart
 * anyway, so a persisted session could not be resumed).
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { customAlphabet } from 'nanoid';
import {
  generateKeypair,
  deriveSharedSecret,
  deriveRoutingId,
  deriveCodeKey,
  deriveSessionKey,
  transcriptHash,
  keyConfirmationTag,
  verifyKeyConfirmation
} from './crypto.js';
import { validateSessionCode, generateSecureSessionId, logger, covalentDir } from '../security/index.js';

const COVALENT_DIR = covalentDir();
const SESSIONS_FILE = path.join(COVALENT_DIR, 'sessions.json');
const SESSION_TTL_MS = 30 * 60 * 1000;

// Base58 alphabet (no ambiguous characters: 0, O, I, l)
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base58Alphabet = customAlphabet(BASE58, 12);

function ensureCovalentBondDir() {
  if (!fs.existsSync(COVALENT_DIR)) {
    fs.mkdirSync(COVALENT_DIR, { recursive: true, mode: 0o700 });
  }
}

// Generate a cryptographically secure session code: 12 uniform Base58
// characters ≈ 70 bits of entropy
export function generateSessionCode() {
  const code = base58Alphabet();
  return code.match(/.{1,4}/g).join('-');
}

// Earlier builds persisted session state (including key material) to
// sessions.json. That file must not linger on disk: best-effort removal.
function removeLegacySessionsFile() {
  try {
    fs.rmSync(SESSIONS_FILE, { force: true });
  } catch (error) {
    logger.warn('Could not remove legacy sessions file:', error.message);
  }
}

function cleanExpiredSessions(sessions) {
  const now = Date.now();
  const cleaned = {};

  for (const [code, session] of Object.entries(sessions)) {
    if (session.expiresAt > now) {
      cleaned[code] = session;
    }
  }

  return cleaned;
}

/**
 * Session states:
 *   waiting    - host created session, no peer yet
 *   keyed      - session key derived, key confirmation pending
 *   confirmed  - peer proved knowledge of the session key; transfers allowed
 */
export class SessionManager {
  constructor() {
    ensureCovalentBondDir();
    removeLegacySessionsFile();
    this.sessions = {};           // memory-only; secrets never touch disk
    this.currentSession = null;
  }

  /**
   * Create a new session as host.
   * @returns {Object} session (includes code to share out-of-band and routingId for the relay)
   */
  createSession() {
    let code;
    let attempts = 0;

    do {
      code = generateSessionCode();
      validateSessionCode(code);

      if (++attempts >= 10) {
        throw new Error('Failed to generate unique session code after 10 attempts');
      }
    } while (this.sessions[code]);

    const { privateKey, publicKey } = generateKeypair();

    const session = {
      code,                                     // shared with peer out-of-band, NEVER sent to relay
      routingId: deriveRoutingId(code),         // what the relay sees
      sessionId: generateSecureSessionId(),
      privateKey: privateKey.toString('hex'),   // wiped once session key is derived
      publicKey: publicKey.toString('hex'),
      codeKey: deriveCodeKey(code).toString('hex'),
      state: 'waiting',
      role: 'host',
      expiresAt: Date.now() + SESSION_TTL_MS,
      createdAt: Date.now(),
      peerCount: 1
    };

    this.sessions[code] = session;
    this.currentSession = session;
    return session;
  }

  /**
   * Join an existing session as guest: derive the session key from the
   * host's public key and produce our key-confirmation tag.
   * @param {string} code - Session code (shared out-of-band)
   * @param {string} hostPublicKey - Host's raw public key (hex, from relay)
   * @param {Object} [keypair] - Pre-generated keypair (when our public key
   *   was already sent to the relay during join)
   * @returns {Object} { session, confirmationTag }
   */
  joinSession(code, hostPublicKey, keypair) {
    validateSessionCode(code);

    const { privateKey, publicKey } = keypair || generateKeypair();

    const codeKey = deriveCodeKey(code);
    const sharedSecret = deriveSharedSecret(privateKey, hostPublicKey);
    const transcript = transcriptHash(hostPublicKey, publicKey);
    const sessionKey = deriveSessionKey(sharedSecret, codeKey, transcript);

    const session = {
      code,
      routingId: deriveRoutingId(code),
      sessionId: generateSecureSessionId(),
      publicKey: publicKey.toString('hex'),
      peerPublicKey: hostPublicKey,
      transcript: transcript.toString('hex'),
      sessionKey: sessionKey.toString('hex'),
      state: 'keyed',
      role: 'guest',
      expiresAt: Date.now() + SESSION_TTL_MS,
      createdAt: Date.now(),
      peerCount: 2
    };

    this.sessions[code] = session;
    this.currentSession = session;
    return {
      session,
      confirmationTag: keyConfirmationTag(sessionKey, 'guest', transcript)
    };
  }

  /**
   * Complete key exchange as host when the guest's public key arrives.
   * @param {string} code - Session code
   * @param {string} guestPublicKey - Guest's raw public key (hex)
   * @returns {Object} { session, confirmationTag } host's own confirmation tag
   */
  completeKeyExchange(code, guestPublicKey) {
    const session = this.sessions[code];

    if (!session || session.role !== 'host') {
      throw new Error('Can only complete key exchange as host');
    }
    if (!session.privateKey) {
      throw new Error('Key exchange already completed for this session');
    }

    const codeKey = Buffer.from(session.codeKey, 'hex');
    const sharedSecret = deriveSharedSecret(session.privateKey, guestPublicKey);
    const transcript = transcriptHash(session.publicKey, guestPublicKey);
    const sessionKey = deriveSessionKey(sharedSecret, codeKey, transcript);

    session.peerPublicKey = guestPublicKey;
    session.transcript = transcript.toString('hex');
    session.sessionKey = sessionKey.toString('hex');
    session.state = 'keyed';
    session.peerCount = 2;

    // Ephemeral material no longer needed once the session key exists
    delete session.privateKey;
    delete session.codeKey;

    return {
      session,
      confirmationTag: keyConfirmationTag(sessionKey, 'host', transcript)
    };
  }

  /**
   * Verify the peer's key-confirmation tag. On success the session is
   * marked confirmed and transfers are allowed.
   * @param {string} code - Session code
   * @param {string} tag - Peer's confirmation tag (hex)
   * @returns {boolean} true if the peer proved knowledge of the session key
   */
  confirmPeer(code, tag) {
    const session = this.sessions[code];

    if (!session || session.state === 'waiting') {
      throw new Error('No keyed session to confirm');
    }

    const peerRole = session.role === 'host' ? 'guest' : 'host';
    const ok = verifyKeyConfirmation(
      Buffer.from(session.sessionKey, 'hex'),
      peerRole,
      Buffer.from(session.transcript, 'hex'),
      tag
    );

    if (ok) {
      session.state = 'confirmed';
      // Guest keeps no ephemeral material either once confirmed
      delete session.privateKey;
      delete session.codeKey;
    }

    return ok;
  }

  /**
   * Whether the current session has completed key confirmation.
   */
  isConfirmed() {
    const session = this.getCurrentSession();
    return !!session && session.state === 'confirmed';
  }

  getCurrentSession() {
    if (!this.currentSession) {
      return null;
    }

    if (this.currentSession.expiresAt < Date.now()) {
      this.clearSession();
      return null;
    }

    return this.currentSession;
  }

  clearSession() {
    if (this.currentSession) {
      delete this.sessions[this.currentSession.code];
    }

    this.currentSession = null;
  }

  getSession(code) {
    const session = this.sessions[code];

    if (!session || session.expiresAt < Date.now()) {
      return null;
    }

    return session;
  }

  refreshSession(code) {
    const session = this.sessions[code];

    if (session) {
      session.expiresAt = Date.now() + SESSION_TTL_MS;
    }
  }

  getActiveSessions() {
    this.sessions = cleanExpiredSessions(this.sessions);
    return Object.keys(this.sessions);
  }
}
