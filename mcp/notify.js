/**
 * Covalent Bond Desktop Notifications
 *
 * Fires a native OS toast when a peer event arrives (incoming file, message,
 * disconnect) so the human is alerted even when the agent is idle; the
 * "phone ringing on the desk" for a session sitting in a background window.
 *
 * SECURITY DESIGN:
 * - Notifications are alert-only. They never carry peer-controlled content:
 *   the title and body are built exclusively from a fixed template, a
 *   whitelist-sanitized filename/size, and an 8-hex-char peer prefix. No
 *   message text, no raw filenames, so nothing a peer types can reach a shell.
 * - Every spawn is fire-and-forget (detached, stdio ignored) and wrapped in
 *   try/catch: a broken notifier must never break the protocol loop.
 * - No stdout: this module is loaded by the MCP server.
 * - Opt-out: COVALENT_NOTIFICATIONS=off|false|0 disables all toasts.
 * - No new dependencies: PowerShell (Windows), osascript (macOS),
 *   notify-send (Linux), all shipped with the OS.
 */

import { spawn } from 'child_process';
import { logger } from '../security/index.js';

const TITLE = 'Covalent Bond';

/** Whether notifications are enabled (checked per call so tests can toggle). */
export function notificationsEnabled(env = process.env) {
  const flag = String(env.COVALENT_NOTIFICATIONS || '').toLowerCase();
  return !['off', 'false', '0', 'no'].includes(flag);
}

/**
 * Reduce an untrusted string to a safe display token: whitelist characters,
 * cap length. Used for filenames only; peer message text is NEVER shown.
 */
export function safeDisplayToken(value, maxLength = 40) {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(/[^A-Za-z0-9._ -]/g, '');
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}

/**
 * Build the notification body from a fixed template per event kind.
 * Only pre-sanitized tokens are interpolated.
 *
 * @param {'file'|'message'|'disconnect'|'connected'} kind
 * @param {string} peerPrefix - first 8 chars of the peer ID (hex)
 * @param {Object} [detail] - { filename?, sizeFormatted? } (already formatted)
 * @returns {string|null} body text, or null for unknown kinds
 */
export function buildNotificationBody(kind, peerPrefix, detail = {}) {
  const peer = /^[0-9a-f]{8}$/.test(peerPrefix || '') ? peerPrefix : 'peer';

  switch (kind) {
    case 'file': {
      const name = safeDisplayToken(detail.filename) || 'a file';
      const size = safeDisplayToken(String(detail.sizeFormatted || ''), 16);
      return `Incoming file from ${peer}…: ${name}${size ? ` (${size})` : ''}, review it in your agent session`;
    }
    case 'message':
      return `New message from ${peer}…, ask your agent for bond_status to read it`;
    case 'disconnect':
      return `Peer ${peer}… disconnected from the session`;
    case 'connected':
      return `Secure channel established with ${peer}…`;
    default:
      return null;
  }
}

/**
 * Platform-specific notifier command. Exported for tests; the body has
 * already been reduced to safe characters by the builders above, but each
 * platform path still passes it as a single argv element (never through a
 * shell string), so quoting is not load-bearing.
 * @returns {{cmd: string, args: string[]}|null}
 */
export function buildNotifierCommand(body, platform = process.platform) {
  switch (platform) {
    case 'win32': {
      // PowerShell WinRT toast. The body is passed via an environment
      // variable read inside the script; it never appears in the command
      // line, so no PowerShell-quoting can be subverted.
      const script = [
        '$ErrorActionPreference="SilentlyContinue";',
        '[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;',
        '$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);',
        '$n=$t.GetElementsByTagName("text");',
        `$n.Item(0).AppendChild($t.CreateTextNode("${TITLE}")) | Out-Null;`,
        '$n.Item(1).AppendChild($t.CreateTextNode($env:COVALENT_TOAST_BODY)) | Out-Null;',
        '$toast=[Windows.UI.Notifications.ToastNotification]::new($t);',
        `[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("${TITLE}").Show($toast);`
      ].join('');
      return { cmd: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command', script], env: { COVALENT_TOAST_BODY: body } };
    }
    case 'darwin':
      return { cmd: 'osascript', args: ['-e', 'on run argv', '-e', 'display notification (item 1 of argv) with title (item 2 of argv)', '-e', 'end run', body, TITLE] };
    case 'linux':
      return { cmd: 'notify-send', args: ['--app-name', TITLE, TITLE, body] };
    default:
      return null;
  }
}

/**
 * Fire a desktop notification. Never throws; never blocks.
 * @param {'file'|'message'|'disconnect'|'connected'} kind
 * @param {string} peerId - full peer ID; only the first 8 chars are shown
 * @param {Object} [detail]
 * @returns {boolean} whether a notification was attempted
 */
export function notifyDesktop(kind, peerId, detail = {}) {
  try {
    if (!notificationsEnabled()) return false;

    const prefix = String(peerId || '').slice(0, 8);
    const body = buildNotificationBody(kind, prefix, detail);
    if (!body) return false;

    const command = buildNotifierCommand(body);
    if (!command) return false;

    const child = spawn(command.cmd, command.args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      env: { ...process.env, ...(command.env || {}) }
    });
    child.on('error', () => { /* notifier missing; never break the protocol */ });
    child.unref();
    return true;
  } catch (error) {
    logger.warn('Desktop notification failed:', error.message);
    return false;
  }
}
