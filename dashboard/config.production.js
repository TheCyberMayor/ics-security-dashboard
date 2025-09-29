// Production Configuration for DigitalOcean Deployment
const PRODUCTION_CONFIG = {
  API_BASE: window.location.hostname.includes('ondigitalocean.app') 
    ? 'https://your-backend-api.ondigitalocean.app/api'  // Update when backend is deployed
    : window.location.origin + '/api',
  WS_URL: window.location.hostname.includes('ondigitalocean.app')
    ? 'wss://your-backend-api.ondigitalocean.app/ws'    // Update when backend is deployed
    : `ws://${window.location.host}/ws`,
  UPDATE_INTERVAL: 5000,
  DEMO_MODE: true, // Keep true for static deployment
  ENVIRONMENT: 'production'
};

// Override CONFIG if in production
if (window.location.hostname.includes('ondigitalocean.app') || 
    window.location.hostname !== 'localhost') {
  Object.assign(CONFIG, PRODUCTION_CONFIG);
  console.log('🚀 Running in production mode');
}