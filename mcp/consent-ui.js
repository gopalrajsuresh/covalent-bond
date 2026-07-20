/**
 * Covalent Bond MCP Consent UI
 * Generates formatted text responses for the MCP client (no OS popups)
 */

/**
 * Generate consent prompt for incoming file transfer
 * Returns formatted text asking user to call bond_accept or bond_decline
 *
 * @param {Object} consentData - Consent data from FileReceiver.processIncomingTransfer()
 * @returns {string} Formatted consent prompt for MCP response
 */
export function generateConsentPrompt(consentData) {
  const { transferId, consentMessage } = consentData;

  const lines = [
    consentMessage,  // Already formatted by transfer/preview.js
    '',
    '═══════════════════════════════════════════',
    '📋 Actions Available:',
    '═══════════════════════════════════════════',
    '',
    `To accept: Call tool bond_accept with transferId: "${transferId}"`,
    `To decline: Call tool bond_decline with transferId: "${transferId}"`,
    '',
    'Ask the user before accepting. Do not accept on your own.',
    '',
    `Transfer ID: ${transferId}`,
    ''
  ];

  return lines.join('\n');
}

/**
 * Generate success message for accepted transfer
 * Shows file location and content injection confirmation
 *
 * @param {Object} acceptResult - Result from FileReceiver.acceptTransfer()
 * @returns {string} Formatted success message
 */
export function generateAcceptSuccess(acceptResult) {
  const { filename, filepath, senderPeerId, message, preview } = acceptResult;

  const lines = [
    '═══════════════════════════════════════════',
    '✅ File Transfer Accepted',
    '═══════════════════════════════════════════',
    '',
    `File: ${filename}`,
    `From: ${senderPeerId.substring(0, 8)}...`,
    `Size: ${preview.sizeFormatted} (${preview.lineCount} lines)`,
    `Saved to: ${filepath}`,
    ''
  ];

  if (message) {
    lines.push(`Sender's message: "${message}"`);
    lines.push('');
  }

  lines.push('📥 File content is included below, wrapped as untrusted data.');
  lines.push('You can now reference this file in your conversation.');
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate decline confirmation message
 *
 * @param {Object} declineResult - Result from FileReceiver.declineTransfer()
 * @returns {string} Formatted decline message
 */
export function generateDeclineConfirmation(declineResult) {
  const { filename } = declineResult;

  const lines = [
    '═══════════════════════════════════════════',
    '❌ File Transfer Declined',
    '═══════════════════════════════════════════',
    '',
    `File: ${filename}`,
    '',
    'Transfer has been declined and removed from pending queue.',
    'The sender will not be notified.',
    ''
  ];

  return lines.join('\n');
}

/**
 * Generate session status message
 *
 * @param {Object} session - Current session from SessionManager
 * @param {Array} pendingTransfers - Pending transfers from FileReceiver
 * @param {number} peerCount - Connected peer count
 * @returns {string} Formatted status message
 */
const STATE_LABELS = {
  waiting: '⏳ Waiting for peer to join',
  keyed: '🔑 Key exchange done - confirming peer knows the session code',
  confirmed: '🔐 Secure channel established (peer verified)'
};

export function generateStatusMessage(session, pendingTransfers = [], unreadEvents = 0) {
  if (!session) {
    return [
      '═══════════════════════════════════════════',
      '📡 Covalent Bond Status',
      '═══════════════════════════════════════════',
      '',
      'Status: Not connected',
      '',
      'Use bond_connect to create a new session,',
      'or bond_join to join an existing session.',
      ''
    ].join('\n');
  }

  const lines = [
    '═══════════════════════════════════════════',
    '📡 Covalent Bond Status',
    '═══════════════════════════════════════════',
    ''
  ];

  if (unreadEvents > 0) {
    lines.push(`📨 ${unreadEvents} unread event(s), shown at the end of this response.`);
    lines.push('');
  }

  lines.push(
    `Session Code: ${session.code}`,
    `Role: ${session.role}`,
    `Handshake: ${session.peerDisconnected
      ? '👋 Peer disconnected. The secure channel is closed. Use bond_end to clean up.'
      : (STATE_LABELS[session.state] || session.state)}`,
    `Connected Peers: ${session.peerCount}`,
    `Expires: ${new Date(session.expiresAt).toLocaleString()}`,
    ''
  );

  if (pendingTransfers.length > 0) {
    lines.push('📥 Pending Transfers:');
    lines.push('───────────────────────────────────────────');

    for (const transfer of pendingTransfers) {
      lines.push(`  • ${transfer.filename} (${transfer.size}) from ${transfer.from}`);
      lines.push(`    Transfer ID: ${transfer.transferId}`);
    }

    lines.push('');
    lines.push('Use bond_accept or bond_decline to handle transfers.');
    lines.push('');
  } else {
    lines.push('No pending transfers.');
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Generate connection success message
 *
 * @param {string} sessionCode - Session code
 * @param {boolean} isCreator - Whether this agent created the session
 * @returns {string} Formatted connection message
 */
export function generateConnectionSuccess(sessionCode, isCreator = true) {
  const lines = [
    '═══════════════════════════════════════════',
    isCreator ? '🔗 Session Created' : '🔗 Session Joined',
    '═══════════════════════════════════════════',
    '',
    `Session Code: ${sessionCode}`,
    ''
  ];

  if (isCreator) {
    lines.push('Share this code with the other agent OUT-OF-BAND (chat, voice).');
    lines.push('The code is the secret that authenticates the connection;');
    lines.push('it is never sent to the relay.');
    lines.push('The other agent should call: bond_join with this code.');
    lines.push('');
    lines.push('The secure channel activates automatically once the peer joins');
    lines.push('and key confirmation succeeds (check with bond_status).');
  } else {
    lines.push('Join request sent. Waiting for the host to confirm the');
    lines.push('shared session key. File transfers unlock once bond_status');
    lines.push('shows "Secure channel established".');
  }

  lines.push('');
  lines.push('Session expires in 30 minutes.');
  lines.push('Use bond_status to check connection status.');
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate send success message
 *
 * @param {Object} sendResult - Result from FileSender.sendFile()
 * @param {string} message - Optional message sent with file
 * @returns {string} Formatted send confirmation
 */
export function generateSendSuccess(sendResult, message = '') {
  const { filename, sizeFormatted } = sendResult;

  const lines = [
    '═══════════════════════════════════════════',
    '📤 File Sent',
    '═══════════════════════════════════════════',
    '',
    `File: ${filename}`,
    `Size: ${sizeFormatted}`,
    ''
  ];

  if (message) {
    lines.push(`Message: "${message}"`);
    lines.push('');
  }

  lines.push('File has been encrypted and sent to connected agent.');
  lines.push('The recipient will see a consent prompt before accepting.');
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate disconnect confirmation
 *
 * @returns {string} Formatted disconnect message
 */
export function generateDisconnectConfirmation() {
  return [
    '═══════════════════════════════════════════',
    '👋 Session Ended',
    '═══════════════════════════════════════════',
    '',
    'You have disconnected from the Covalent Bond session.',
    'All pending transfers have been cleared.',
    '',
    'Use bond_connect or bond_join to start a new session.',
    ''
  ].join('\n');
}

/**
 * Generate error message
 *
 * @param {string} toolName - Tool that errored
 * @param {Error|string} error - Error object or message
 * @returns {string} Formatted error message
 */
export function generateErrorMessage(toolName, error) {
  const errorMsg = error instanceof Error ? error.message : error;

  return [
    '═══════════════════════════════════════════',
    `❌ Error: ${toolName}`,
    '═══════════════════════════════════════════',
    '',
    errorMsg,
    ''
  ].join('\n');
}
