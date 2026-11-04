// Neon Functions entry: runs the same server.js (accounts, approvals, backup, labs) as on Render.
// Neon calls fetch(request) and expects a Response; this turns it into the request/response pair server.js expects.
// Neon injects DATABASE_URL for the branch the function is deployed on. Other settings come from --env at deploy time.
import { Readable } from 'node:stream';
import srv from '../server.js';

let ready = null; // database tables are checked once per running copy
const init = () => (ready ||= srv.store.init().catch(e => { ready = null; throw e; }));

export default {
  async fetch(request) {
    try { await init(); } catch (e) {
      console.error('Database setup failed:', e);
      return Response.json({ error: 'unavailable', message: 'Server is starting — try again' }, { status: 503 });
    }
    const url = new URL(request.url);
    const body = request.method === 'GET' || request.method === 'HEAD' ? null : Buffer.from(await request.arrayBuffer());
    const req = Readable.from(body && body.length ? [body] : []);
    req.method = request.method;
    req.url = url.pathname + url.search;
    req.headers = {};
    request.headers.forEach((v, k) => { req.headers[k.toLowerCase()] = v; });
    req.socket = { remoteAddress: '' }; // the caller's address comes from x-forwarded-for
    return new Promise(resolve => {
      const headers = new Headers();
      let status = 200;
      const res = {
        headersSent: false,
        setHeader(k, v) { headers.set(k, String(v)); },
        writeHead(s, h) { status = s; Object.entries(h || {}).forEach(([k, v]) => headers.set(k, String(v))); this.headersSent = true; },
        end(b) { resolve(new Response(status === 204 || b == null ? null : b, { status, headers })); }
      };
      srv.dispatch(req, res);
    });
  }
};
