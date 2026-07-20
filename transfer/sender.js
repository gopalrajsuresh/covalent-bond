/**
 * Covalent Bond File Sender
 * Handles outbound file transfers with security validation and rate limiting
 */

import fs from 'fs';
import path from 'path';
import { encrypt, generateNonce } from '../daemon/crypto.js';
import { validateOutbound, auditToolCall, logger } from '../security/index.js';
import { generatePreview, generateSummary } from './preview.js';

/**
 * File Sender Class
 * Rate-limit state is per instance: one FileSender per connected endpoint,
 * enforcing a 10-second cooldown between its own sends.
 */
export class FileSender {
  constructor(relayClient, sessionManager) {
    this.relayClient = relayClient;
    this.sessionManager = sessionManager;
    this.lastSendTimes = new Map();
  }

  /**
   * Send a file to connected peer
   *
   * @param {string} filepath - Path to file to send
   * @param {string} message - Optional message to recipient
   * @returns {Promise<Object>} Send result
   */
  async sendFile(filepath, message = '') {
    const session = this.sessionManager.getCurrentSession();

    if (!session) {
      throw new Error('No active session - cannot send file');
    }

    if (session.state !== 'confirmed') {
      throw new Error('Session key not confirmed yet - wait for the peer handshake to complete');
    }

    const rateLimitCheck = this.checkRateLimit(session.code);
    if (!rateLimitCheck.allowed) {
      throw new Error(`Rate limit: please wait ${rateLimitCheck.wait} seconds before sending again`);
    }

    const content = await this.readFile(filepath);
    const filename = path.basename(filepath);

    // SECURITY: Validate outbound transfer
    try {
      validateOutbound(filepath, content, session.code);
    } catch (error) {
      // Audit by routing ID: the session code is a secret and must not be
      // persisted to the audit log.
      auditToolCall('sendFile_blocked', {
        file: filename,
        reason: error.message,
        routing: session.routingId.substring(0, 12)
      }, 'security');

      throw new Error(`File blocked by security: ${error.message}`);
    }

    const preview = generatePreview(filename, content);
    const summary = generateSummary(preview);

    logger.info(`Sending: ${summary}`);

    const transferPacket = {
      type: 'file_transfer',
      nonce: generateNonce(),
      timestamp: Date.now(),
      filename,
      content: content.toString('utf8'),
      message,
      preview: {
        filename: preview.filename,
        size: preview.size,
        sizeFormatted: preview.sizeFormatted,
        fileType: preview.fileType,
        lineCount: preview.lineCount
      }
    };

    const encrypted = encrypt(JSON.stringify(transferPacket), session.sessionKey);

    await this.relayClient.send(encrypted);

    this.sessionManager.refreshSession(session.code);
    this.updateRateLimit(session.code);

    auditToolCall('sendFile', {
      file: filename,
      size: preview.size,
      routing: session.routingId.substring(0, 12),
      // Length only: the audit log records that a message accompanied the
      // file, not its content (same policy as the bond_message audit).
      messageChars: (message || '').length
    }, 'user');

    return {
      success: true,
      filename,
      size: preview.size,
      sizeFormatted: preview.sizeFormatted
    };
  }

  /**
   * Read file from filesystem
   * @param {string} filepath - File path
   * @returns {Promise<Buffer>} File content
   */
  async readFile(filepath) {
    try {
      return fs.readFileSync(filepath);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new Error(`File not found: ${filepath}`);
      }
      if (error.code === 'EACCES') {
        throw new Error(`Permission denied: ${filepath}`);
      }
      throw new Error(`Failed to read file: ${error.message}`);
    }
  }

  /**
   * Check rate limit for session
   * @param {string} sessionCode - Session code
   * @returns {Object} { allowed: boolean, wait?: number }
   */
  checkRateLimit(sessionCode) {
    const lastSend = this.lastSendTimes.get(sessionCode) || 0;
    const now = Date.now();
    const cooldown = 10000; // 10 seconds

    if (now - lastSend < cooldown) {
      return {
        allowed: false,
        wait: Math.ceil((cooldown - (now - lastSend)) / 1000)
      };
    }

    return { allowed: true };
  }

  /**
   * Update rate limit timestamp
   * @param {string} sessionCode - Session code
   */
  updateRateLimit(sessionCode) {
    this.lastSendTimes.set(sessionCode, Date.now());
  }

  /**
   * Clear rate limit for session (e.g., on disconnect)
   * @param {string} sessionCode - Session code
   */
  clearRateLimit(sessionCode) {
    this.lastSendTimes.delete(sessionCode);
  }

  /**
   * Get remaining cooldown time
   * @param {string} sessionCode - Session code
   * @returns {number} Seconds remaining (0 if can send now)
   */
  getRemainingCooldown(sessionCode) {
    const lastSend = this.lastSendTimes.get(sessionCode) || 0;
    const now = Date.now();
    const cooldown = 10000;
    const remaining = cooldown - (now - lastSend);

    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }
}
