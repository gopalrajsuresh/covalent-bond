/**
 * Covalent Bond File Preview Generator
 * Creates human-readable previews for consent UI
 */

import path from 'path';

/**
 * Generate preview for file content
 * Shows first N lines for code files, summary for others
 *
 * @param {string} filename - File name
 * @param {string|Buffer} content - File content
 * @param {Object} options - Preview options
 * @returns {Object} Preview object
 */
export function generatePreview(filename, content, options = {}) {
  const {
    maxLines = 20,        // Max lines to show
    maxChars = 2000,      // Max characters per line
  } = options;

  const ext = path.extname(filename).toLowerCase();
  const basename = path.basename(filename);
  const contentStr = typeof content === 'string' ? content : content.toString('utf8');
  const size = Buffer.byteLength(content);

  // Determine file type
  const fileType = getFileType(ext);

  // Generate preview based on type
  let preview;
  let isTruncated = false;

  if (fileType === 'code' || fileType === 'text') {
    const result = generateTextPreview(contentStr, maxLines, maxChars);
    preview = result.preview;
    isTruncated = result.truncated;
  } else if (fileType === 'json') {
    const result = generateJsonPreview(contentStr, maxLines);
    preview = result.preview;
    isTruncated = result.truncated;
  } else if (fileType === 'markdown') {
    const result = generateMarkdownPreview(contentStr, maxLines);
    preview = result.preview;
    isTruncated = result.truncated;
  } else {
    preview = `[Binary file - ${formatSize(size)}]`;
  }

  return {
    filename: basename,
    fileType,
    extension: ext,
    size,
    sizeFormatted: formatSize(size),
    preview,
    isTruncated,
    lineCount: contentStr.split('\n').length
  };
}

/**
 * Determine file type from extension
 * @param {string} ext - File extension
 * @returns {string} File type category
 */
function getFileType(ext) {
  const codeExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rs', '.c', '.cpp', '.h'];
  const textExtensions = ['.txt', '.log', '.csv', '.tsv'];

  if (codeExtensions.includes(ext)) return 'code';
  if (textExtensions.includes(ext)) return 'text';
  if (ext === '.json') return 'json';
  if (ext === '.md') return 'markdown';
  if (['.yml', '.yaml', '.toml', '.ini', '.conf'].includes(ext)) return 'config';

  return 'unknown';
}

/**
 * Generate preview for text/code files
 * @param {string} content - File content
 * @param {number} maxLines - Max lines to show
 * @param {number} maxChars - Max chars per line
 * @returns {Object} { preview, truncated }
 */
function generateTextPreview(content, maxLines, maxChars) {
  const lines = content.split('\n');
  const previewLines = lines.slice(0, maxLines);

  const truncatedLines = previewLines.map(line => {
    if (line.length > maxChars) {
      return line.substring(0, maxChars) + '...';
    }
    return line;
  });

  const truncated = lines.length > maxLines;
  const preview = truncatedLines.join('\n');

  return {
    preview: truncated ? preview + `\n\n... (${lines.length - maxLines} more lines)` : preview,
    truncated
  };
}

/**
 * Generate preview for JSON files
 * Pretty-prints and truncates
 * @param {string} content - JSON content
 * @param {number} maxLines - Max lines to show
 * @returns {Object} { preview, truncated }
 */
function generateJsonPreview(content, maxLines) {
  try {
    const parsed = JSON.parse(content);
    const pretty = JSON.stringify(parsed, null, 2);
    return generateTextPreview(pretty, maxLines, 2000);
  } catch (error) {
    return generateTextPreview(content, maxLines, 2000);
  }
}

/**
 * Generate preview for Markdown files
 * Shows headings and first paragraph
 * @param {string} content - Markdown content
 * @param {number} maxLines - Max lines to show
 * @returns {Object} { preview, truncated }
 */
function generateMarkdownPreview(content, maxLines) {
  const lines = content.split('\n');

  const headings = lines
    .filter(line => line.trim().startsWith('#'))
    .slice(0, 5)
    .map(h => h.trim());

  let preview = '';

  if (headings.length > 0) {
    preview = 'Headings:\n' + headings.join('\n') + '\n\n';
  }

  const previewLines = lines.slice(0, maxLines);
  preview += previewLines.join('\n');

  const truncated = lines.length > maxLines;

  return {
    preview: truncated ? preview + `\n\n... (${lines.length - maxLines} more lines)` : preview,
    truncated
  };
}

/**
 * Format file size in human-readable format
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size
 */
function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Generate consent message for user
 * @param {Object} previewData - Preview object from generatePreview()
 * @param {string} senderName - Name/ID of sender
 * @param {string} message - Optional message from sender
 * @returns {string} Formatted consent message
 */
export function generateConsentMessage(previewData, senderName, message = '') {
  const lines = [
    '═══════════════════════════════════════════',
    '🔔 Incoming File Transfer',
    '═══════════════════════════════════════════',
    '',
    `From: ${senderName}`,
    `File: ${previewData.filename}`,
    `Type: ${previewData.fileType}`,
    `Size: ${previewData.sizeFormatted} (${previewData.lineCount} lines)`,
    ''
  ];

  if (message) {
    lines.push(`Message: "${message}"`);
    lines.push('');
  }

  lines.push('Preview:');
  lines.push('───────────────────────────────────────────');
  lines.push(previewData.preview);
  lines.push('───────────────────────────────────────────');
  lines.push('');
  lines.push('Accept this file? [y/n]');
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate summary for logging
 * @param {Object} previewData - Preview object
 * @returns {string} One-line summary
 */
export function generateSummary(previewData) {
  return `${previewData.filename} (${previewData.fileType}, ${previewData.sizeFormatted})`;
}
