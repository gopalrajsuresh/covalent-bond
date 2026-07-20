/**
 * Covalent Bond MCP Tool Definitions
 * Defines the bond_* MCP tool schemas
 */

/**
 * MCP Tool Schemas
 * These tools are exposed to the MCP client by the server
 */

export const TOOLS = [
  {
    name: 'bond_connect',
    description: 'Create a new Covalent Bond session and get a shareable session code. The other agent will use this code to join.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },

  {
    name: 'bond_join',
    description: 'Join an existing Covalent Bond session using a session code (format: XXXX-XXXX-XXXX Base58, e.g., "3KPz-QR7m-8WXn"). Call this when the user provides a session code from another agent. The code is a shared secret - it authenticates the encrypted channel and is never sent to the relay.',
    inputSchema: {
      type: 'object',
      properties: {
        sessionCode: {
          type: 'string',
          description: 'Session code in format XXXX-XXXX-XXXX (Base58, e.g., "3KPz-QR7m-8WXn")',
          pattern: '^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4}-[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4}-[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4}$'
        }
      },
      required: ['sessionCode']
    }
  },

  {
    name: 'bond_send',
    description: 'Send a file to the connected agent. File will be encrypted and delivered with an optional message. Subject to 10-second rate limit and security validation (file type whitelist, 256KB default size limit, configurable via COVALENT_MAX_FILE_KB).',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Absolute path to file to send'
        },
        message: {
          type: 'string',
          description: 'Optional message to recipient explaining the file context'
        }
      },
      required: ['filepath']
    }
  },

  {
    name: 'bond_accept',
    description: 'Accept a pending file transfer. File will be written to ~/.covalent/incoming/ and its content returned, wrapped in untrusted-data markers.',
    inputSchema: {
      type: 'object',
      properties: {
        transferId: {
          type: 'string',
          description: 'Transfer ID from the consent prompt'
        }
      },
      required: ['transferId']
    }
  },

  {
    name: 'bond_decline',
    description: 'Decline a pending file transfer. File will be discarded and sender will not be notified.',
    inputSchema: {
      type: 'object',
      properties: {
        transferId: {
          type: 'string',
          description: 'Transfer ID from the consent prompt'
        }
      },
      required: ['transferId']
    }
  },

  {
    name: 'bond_message',
    description: 'Send a short encrypted text message to the connected agent (no file involved). Use this for agent-to-agent conversation: questions, context, summaries. Requires a confirmed session. Max 4000 characters.',
    inputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'string',
          description: 'Message text to send to the peer (max 4000 characters)',
          maxLength: 4000
        }
      },
      required: ['content']
    }
  },

  {
    name: 'bond_wait',
    description: 'Wait (long-poll) until the next event arrives from the peer (a message, incoming file, or disconnect) or until the timeout passes. Use this in a loop to hold a live conversation with the other agent: call bond_wait, react to what it returns, reply, call bond_wait again. Returns immediately if events are already queued. This costs tokens per call, so loop only during an active conversation; for idle waiting rely on desktop notifications and bond_status.',
    inputSchema: {
      type: 'object',
      properties: {
        timeoutSeconds: {
          type: 'number',
          description: 'How long to wait before returning if nothing arrives (default 50, min 1, max 300; note some MCP clients cap tool calls at 60s)'
        }
      },
      required: []
    }
  },

  {
    name: 'bond_status',
    description: 'Get current Covalent Bond connection status: session info, handshake state, pending file transfers, and any events (incoming transfers, peer messages) that arrived since the last tool call. Call this periodically while connected to pick up incoming transfers.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },

  {
    name: 'bond_end',
    description: 'End the current Covalent Bond session and disconnect from relay. Clears all pending transfers.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  }
];

/**
 * Validate tool call arguments against schema
 * @param {string} toolName - Tool name
 * @param {Object} args - Tool arguments
 * @returns {Object} { valid: boolean, error?: string }
 */
export function validateToolArgs(toolName, args) {
  const tool = TOOLS.find(t => t.name === toolName);

  if (!tool) {
    return { valid: false, error: `Unknown tool: ${toolName}` };
  }

  const { inputSchema } = tool;
  const required = inputSchema.required || [];

  // Check required fields
  for (const field of required) {
    if (!(field in args)) {
      return { valid: false, error: `Missing required field: ${field}` };
    }
  }

  // Type validation
  for (const [key, value] of Object.entries(args)) {
    const propSchema = inputSchema.properties[key];

    if (!propSchema) {
      return { valid: false, error: `Unknown argument: ${key}` };
    }

    // String type check
    if (propSchema.type === 'string' && typeof value !== 'string') {
      return { valid: false, error: `${key} must be a string` };
    }

    // Number type check (rejects NaN and non-finite values)
    if (propSchema.type === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) {
      return { valid: false, error: `${key} must be a finite number` };
    }

    // Length cap (e.g., message content)
    if (propSchema.maxLength && typeof value === 'string' && value.length > propSchema.maxLength) {
      return { valid: false, error: `${key} exceeds maximum length of ${propSchema.maxLength} characters` };
    }

    // Pattern validation (e.g., session code format)
    if (propSchema.pattern && !new RegExp(propSchema.pattern).test(value)) {
      return { valid: false, error: `${key} has invalid format (expected: ${propSchema.pattern})` };
    }
  }

  return { valid: true };
}

/**
 * Get tool by name
 * @param {string} name - Tool name
 * @returns {Object|null} Tool definition
 */
export function getTool(name) {
  return TOOLS.find(t => t.name === name) || null;
}
