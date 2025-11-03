// Application constants
export const SUPPORT_DOMAINS = {
  GENERAL: 'general',
  TECHNICAL: 'technical', 
  FINANCE: 'finance',
  TRAVEL: 'travel',
  ADMIN: 'admin'
};

export const DOMAIN_LABELS = {
  [SUPPORT_DOMAINS.GENERAL]: 'General Customer Support',
  [SUPPORT_DOMAINS.TECHNICAL]: 'Technical Support',
  [SUPPORT_DOMAINS.FINANCE]: 'Finance',
  [SUPPORT_DOMAINS.TRAVEL]: 'Travel Support',
  [SUPPORT_DOMAINS.ADMIN]: 'Admin Dashboard'
};

export const SOCKET_EVENTS = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  MESSAGE: 'message',
  TYPING: 'typing',
  STOP_TYPING: 'stop_typing',
  AGENT_AVAILABLE: 'agent_available',
  AGENT_CONNECTED: 'agent_connected'
};

export const USER_ROLES = {
  USER: 'user',
  ADMIN: 'admin'
};