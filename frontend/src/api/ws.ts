import { API_HOST } from './client';

/**
 * Build a WebSocket URL for the backend.
 * - Dev: API_HOST is empty → use the current page host (Vite proxies /ws → backend).
 * - Prod: VITE_API_URL is set to the backend origin → use that host with ws/wss.
 */
export function wsUrl(path: string): string {
  if (API_HOST) {
    const httpUrl = new URL(API_HOST);
    const proto = httpUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${httpUrl.host}${path}`;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${path}`;
}
