import serverless from 'serverless-http';
import app from '../../server.js';

// Netlify rewrites /api/* to /.netlify/functions/api/api/*; strip the function prefix
// so Express receives the original /api/... route.
export const handler = serverless(app, { basePath: '/.netlify/functions/api' });
