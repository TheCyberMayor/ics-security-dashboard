# ICS Security Risk Management Dashboard

A comprehensive Industrial Control Systems (ICS) cybersecurity risk management dashboard implementing a 6-phase methodology with graph-theoretic risk analysis and machine learning-based threat detection.

## 🚀 Live Demo

- **Dashboard**: [Your DigitalOcean URL]/dashboard/
- **Login Page**: [Your DigitalOcean URL]/dashboard/login.html

## 🔐 Demo Credentials

| Role | Username | Password | Access Level |
|------|----------|----------|--------------|
| Administrator | `admin` | `admin123` | Full system access |
| Operator | `operator` | `operator123` | Control room operations |
| Engineer | `engineer` | `engineer123` | System analysis & config |
| Viewer | `viewer` | `viewer123` | Read-only monitoring |

## 🏗️ Architecture

### Frontend
- **Dashboard**: Modern HTML5/CSS3/JavaScript interface
- **Visualization**: vis-network for topology, Chart.js for analytics
- **Authentication**: Role-based access control with session management
- **Real-time Updates**: WebSocket integration for live data

### Backend (Python FastAPI)
- **Phase 1**: Threat Collection & Intelligence Gathering
- **Phase 2**: Graph Analysis with Risk Score Calculation (GRS = NRS + ERS + PRS)
- **Phase 3**: Multi-layered Risk Classification (ML + Rule-based)
- **Phase 4**: Dynamic Mitigation with Reinforcement Learning
- **Phase 5**: Dashboard API with WebSocket support
- **Phase 6**: Validation & Performance Monitoring

## 📊 Risk Management Model

### Graph-Theoretic Risk Score (GRS)
```
GRS = α×NRS + β×ERS + γ×PRS
```

- **NRS (Network Risk Score)**: Centrality-based network position risk
- **ERS (Exposure Risk Score)**: Vulnerability and threat exposure analysis  
- **PRS (Propagation Risk Score)**: Attack path and cascade potential

### Risk Classification
- **Sigmoid Likelihood**: `L(GRS) = 1/(1+e^(-k*(GRS-threshold)))`
- **5-Class Device Risk**: Critical, High, Medium, Low, Minimal
- **Binary Attack Detection**: ML-based anomaly detection

## 🛠️ Installation & Setup

### Local Development
```bash
# Clone the repository
git clone https://github.com/yourusername/ics-security-dashboard.git
cd ics-security-dashboard

# Install Python dependencies
pip install -r backend/requirements.txt

# Start the backend API
cd backend
python main.py

# Serve the frontend (in another terminal)
cd dashboard
python -m http.server 8080
```

### DigitalOcean Deployment

#### Option 1: Static Site Deployment
1. Create a DigitalOcean App Platform application
2. Connect your GitHub repository
3. Set build command: `echo "Static site deployment"`
4. Set output directory: `dashboard`
5. Deploy and access via provided URL

#### Option 2: Full Stack Deployment
1. Deploy backend API to DigitalOcean Droplet or App Platform
2. Update `CONFIG.API_BASE` in `dashboard/script.js`
3. Deploy frontend to App Platform or serve via nginx

## 📁 Project Structure

```
ics-security-dashboard/
├── dashboard/                 # Frontend application
│   ├── index.html            # Main dashboard interface
│   ├── login.html            # Authentication page
│   ├── styles.css            # Dashboard styling
│   ├── login-styles.css      # Login page styling
│   ├── script.js             # Dashboard functionality
│   └── login-script.js       # Authentication logic
├── backend/                  # Python FastAPI backend
│   ├── main.py              # FastAPI application entry
│   ├── phase1_threat_collection.py
│   ├── phase2_graph_analysis.py
│   ├── phase3_risk_classification.py
│   ├── phase4_dynamic_mitigation.py
│   ├── phase5_dashboard_api.py
│   ├── phase6_validation.py
│   └── requirements.txt
├── docs/                    # Documentation
├── tests/                   # Test files
└── README.md
```

## 🔧 Configuration

### Environment Variables
```bash
# Backend Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=False

# Database (if using persistent storage)
DATABASE_URL=postgresql://user:pass@localhost/icsdb

# Security
JWT_SECRET_KEY=your-secret-key
SESSION_TIMEOUT=28800  # 8 hours
```

### Frontend Configuration
Update `dashboard/script.js`:
```javascript
const CONFIG = {
  API_BASE: 'https://your-api-domain.com/api',
  WS_URL: 'wss://your-api-domain.com/ws',
  UPDATE_INTERVAL: 5000
};
```

## 🧪 Testing

```bash
# Run comprehensive tests
python test_core_functionality.py

# Run risk management model demo
python demo_risk_management_model.py

# Start development server
cd dashboard && python -m http.server 8080
```

## 📈 Features

### Dashboard Features
- ✅ Real-time network topology visualization
- ✅ Risk timeline and trend analysis
- ✅ Attack distribution monitoring
- ✅ System health indicators
- ✅ Alert management with filtering
- ✅ Role-based access control
- ✅ Responsive design for all devices

### Security Features
- ✅ Multi-role authentication system
- ✅ Session management with timeout
- ✅ Permission-based feature access
- ✅ Secure credential handling
- ✅ Auto-logout on inactivity

### Analytics Features
- ✅ Graph-theoretic risk scoring
- ✅ Machine learning threat detection
- ✅ Reinforcement learning mitigation
- ✅ Real-time performance monitoring
- ✅ Historical trend analysis

## 🚀 Deployment Guide

### DigitalOcean App Platform
1. Fork this repository to your GitHub account
2. Create new App in DigitalOcean
3. Connect GitHub repository
4. Configure build settings:
   - **Build Command**: `echo "Building static site"`
   - **Output Directory**: `dashboard`
5. Deploy and test with demo credentials

### Custom Domain Setup
1. Add custom domain in DigitalOcean App settings
2. Update DNS records to point to App Platform
3. SSL certificates are automatically provisioned

## 📚 Documentation

- [Project Overview](PROJECT_OVERVIEW.md)
- [Risk Management Model](RISK_MANAGEMENT_MODEL.md)
- [Implementation Mapping](MODEL_IMPLEMENTATION_MAPPING.md)
- [Testing Guide](TESTING_GUIDE.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Links

- **Live Demo**: [Your DigitalOcean URL]
- **GitHub Repository**: https://github.com/yourusername/ics-security-dashboard
- **Documentation**: [Your docs URL]

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Email: your-email@domain.com

---

**Built with ❤️ for Industrial Cybersecurity**