# DigitalOcean App Platform Configuration

## App Settings:
- **App Name**: `ics-security-dashboard`
- **Repository**: `TheCyberMayor/ics-security-dashboard`
- **Branch**: `Master`
- **Source Directory**: `/`

## Static Site Configuration:
- **Type**: Static Site
- **Name**: `dashboard`
- **Source Directory**: `dashboard`
- **Output Directory**: `dashboard`
- **Index Document**: `login.html`
- **Error Document**: `login.html`
- **Build Command**: (leave empty or use `echo "Static site build"`)

## Environment Variables (Optional):
- `NODE_ENV`: `production`
- `API_ENDPOINT`: `https://your-backend-api.com` (if you deploy backend)

## Routing:
- **Route**: `/` (serves from dashboard directory)
- **Catchall**: Redirect to `login.html`

## Estimated Cost:
- **Static Site**: $0/month (within free tier)
- **Custom Domain**: Free SSL certificate included

## Access URLs:
After deployment, you'll get:
- **App URL**: `https://your-app-name-xxxxx.ondigitalocean.app`
- **Dashboard**: `https://your-app-name-xxxxx.ondigitalocean.app/login.html`

## Demo Credentials:
Use these to test the deployed application:
- **Admin**: `admin` / `admin123`
- **Operator**: `operator` / `op123`
- **Engineer**: `engineer` / `eng123`
- **Viewer**: `viewer` / `view123`