#!/bin/bash

# ICS Security Dashboard Deployment Script
# This script helps deploy the dashboard to DigitalOcean

echo "🚀 Deploying ICS Security Dashboard to DigitalOcean"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "dashboard/index.html" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

echo "✅ Project structure verified"

# Update the API configuration for production
echo "🔧 Updating configuration for production..."

# Create production config (this would be updated based on your actual API URL)
cat > dashboard/config.prod.js << EOF
// Production Configuration
const CONFIG = {
  API_BASE: 'https://your-api-domain.com/api',
  WS_URL: 'wss://your-api-domain.com/ws',
  UPDATE_INTERVAL: 5000,
  DEMO_MODE: true // Set to false when backend is deployed
};
EOF

echo "✅ Production configuration created"

echo "📋 Next Steps:"
echo "1. Push your code to GitHub:"
echo "   git add ."
echo "   git commit -m 'Deploy configuration'"
echo "   git push origin main"
echo ""
echo "2. Create DigitalOcean App:"
echo "   - Go to https://cloud.digitalocean.com/apps"
echo "   - Click 'Create App'"
echo "   - Connect your GitHub repository"
echo "   - Select 'Static Site' for deployment"
echo "   - Set output directory to 'dashboard'"
echo ""
echo "3. Access your deployed app:"
echo "   - Use the URL provided by DigitalOcean"
echo "   - Login with demo credentials from README.md"
echo ""
echo "🎉 Deployment preparation complete!"