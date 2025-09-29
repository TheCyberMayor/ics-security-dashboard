// ICS Security Login Script
class LoginManager {
    constructor() {
        this.init();
        this.setupEventListeners();
        this.loadDemoCredentials();
    }

    init() {
        // Demo user accounts with different roles
        this.demoUsers = {
            'admin': {
                password: 'admin123',
                role: 'Administrator',
                permissions: ['full_access', 'user_management', 'system_config', 'security_settings'],
                displayName: 'System Administrator'
            },
            'operator': {
                password: 'op123',
                role: 'Operator',
                permissions: ['monitor_systems', 'basic_controls', 'incident_response'],
                displayName: 'Control Room Operator'
            },
            'engineer': {
                password: 'eng123',
                role: 'Engineer',
                permissions: ['system_analysis', 'configuration', 'diagnostics', 'reports'],
                displayName: 'Systems Engineer'
            },
            'viewer': {
                password: 'view123',
                role: 'Viewer',
                permissions: ['read_only', 'basic_monitoring'],
                displayName: 'Security Analyst'
            }
        };

        // Initialize session storage
        this.sessionKey = 'ics_security_session';
        this.checkExistingSession();
    }

    checkExistingSession() {
        const session = this.getSession();
        if (session && this.isSessionValid(session)) {
            // Auto-redirect if valid session exists
            this.redirectToDashboard();
        }
    }

    setupEventListeners() {
        // Form submission
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Password visibility toggle
        const passwordToggle = document.getElementById('passwordToggle');
        if (passwordToggle) {
            passwordToggle.addEventListener('click', () => this.togglePasswordVisibility());
        }

        // Demo credential quick-fill
        this.setupDemoCredentialHandlers();

        // Form validation
        this.setupFormValidation();

        // Remember me functionality
        this.setupRememberMe();
    }

    setupDemoCredentialHandlers() {
        // Add click handlers to demo credentials for easy testing
        const credentialItems = document.querySelectorAll('.credential-item');
        credentialItems.forEach(item => {
            item.style.cursor = 'pointer';
            item.title = 'Click to auto-fill credentials';
            
            item.addEventListener('click', () => {
                const text = item.textContent;
                const usernameMatch = text.match(/Username:\s*(\w+)/);
                const passwordMatch = text.match(/Password:\s*(\w+)/);
                
                if (usernameMatch && passwordMatch) {
                    document.getElementById('username').value = usernameMatch[1];
                    document.getElementById('password').value = passwordMatch[1];
                    
                    // Set role based on username
                    const roleSelect = document.getElementById('role');
                    const username = usernameMatch[1];
                    const user = this.demoUsers[username];
                    if (user && roleSelect) {
                        roleSelect.value = user.role;
                    }
                    
                    this.showAlert('Credentials auto-filled! Click Login to continue.', 'info');
                }
            });
        });
    }

    setupFormValidation() {
        const inputs = document.querySelectorAll('input, select');
        inputs.forEach(input => {
            input.addEventListener('blur', () => this.validateField(input));
            input.addEventListener('input', () => this.clearFieldError(input));
        });
    }

    setupRememberMe() {
        const rememberCheckbox = document.getElementById('rememberMe');
        const usernameInput = document.getElementById('username');
        
        // Load remembered username
        const rememberedUsername = localStorage.getItem('ics_remembered_username');
        if (rememberedUsername && usernameInput) {
            usernameInput.value = rememberedUsername;
            if (rememberCheckbox) {
                rememberCheckbox.checked = true;
            }
        }
    }

    validateField(field) {
        const value = field.value.trim();
        let isValid = true;
        let errorMessage = '';

        switch (field.id) {
            case 'username':
                if (!value) {
                    errorMessage = 'Username is required';
                    isValid = false;
                } else if (value.length < 3) {
                    errorMessage = 'Username must be at least 3 characters';
                    isValid = false;
                }
                break;
            
            case 'password':
                if (!value) {
                    errorMessage = 'Password is required';
                    isValid = false;
                } else if (value.length < 6) {
                    errorMessage = 'Password must be at least 6 characters';
                    isValid = false;
                }
                break;
            
            case 'role':
                if (!value) {
                    errorMessage = 'Please select a role';
                    isValid = false;
                }
                break;
        }

        this.setFieldError(field, isValid ? null : errorMessage);
        return isValid;
    }

    setFieldError(field, message) {
        const formGroup = field.closest('.form-group');
        let errorElement = formGroup.querySelector('.field-error');
        
        if (message) {
            field.style.borderColor = '#ef4444';
            if (!errorElement) {
                errorElement = document.createElement('span');
                errorElement.className = 'field-error';
                errorElement.style.cssText = 'color: #ef4444; font-size: 12px; margin-top: 4px;';
                formGroup.appendChild(errorElement);
            }
            errorElement.textContent = message;
        } else {
            field.style.borderColor = '#e5e7eb';
            if (errorElement) {
                errorElement.remove();
            }
        }
    }

    clearFieldError(field) {
        field.style.borderColor = '#e5e7eb';
        const formGroup = field.closest('.form-group');
        const errorElement = formGroup.querySelector('.field-error');
        if (errorElement) {
            errorElement.remove();
        }
    }

    async handleLogin(event) {
        event.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const role = document.getElementById('role').value;
        const rememberMe = document.getElementById('rememberMe').checked;

        // Validate all fields
        const fields = [
            document.getElementById('username'),
            document.getElementById('password'),
            document.getElementById('role')
        ];
        
        let allValid = true;
        fields.forEach(field => {
            if (!this.validateField(field)) {
                allValid = false;
            }
        });

        if (!allValid) {
            this.showAlert('Please fix the errors above and try again.', 'error');
            return;
        }

        // Show loading
        this.showLoading('Authenticating...');

        try {
            // Simulate authentication delay
            await this.delay(1500);
            
            // Check credentials
            const authResult = this.authenticateUser(username, password, role);
            
            if (authResult.success) {
                // Handle remember me
                if (rememberMe) {
                    localStorage.setItem('ics_remembered_username', username);
                } else {
                    localStorage.removeItem('ics_remembered_username');
                }
                
                // Create session
                this.createSession(authResult.user);
                
                this.showAlert(`Welcome, ${authResult.user.displayName}!`, 'success');
                
                // Redirect after short delay
                setTimeout(() => {
                    this.redirectToDashboard();
                }, 1000);
                
            } else {
                this.showAlert(authResult.message, 'error');
            }
            
        } catch (error) {
            console.error('Login error:', error);
            this.showAlert('An unexpected error occurred. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    authenticateUser(username, password, selectedRole) {
        const user = this.demoUsers[username.toLowerCase()];
        
        if (!user) {
            return {
                success: false,
                message: 'Invalid username or password.'
            };
        }
        
        if (user.password !== password) {
            return {
                success: false,
                message: 'Invalid username or password.'
            };
        }
        
        if (user.role !== selectedRole) {
            return {
                success: false,
                message: `Role mismatch. This user is assigned as ${user.role}.`
            };
        }
        
        return {
            success: true,
            user: {
                username: username,
                role: user.role,
                permissions: user.permissions,
                displayName: user.displayName,
                loginTime: new Date().toISOString()
            }
        };
    }

    createSession(user) {
        const session = {
            user: user,
            token: this.generateToken(),
            expires: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(), // 8 hours
            created: new Date().toISOString()
        };
        
        sessionStorage.setItem(this.sessionKey, JSON.stringify(session));
        
        // Also store in localStorage for persistence across tabs
        localStorage.setItem(this.sessionKey, JSON.stringify(session));
    }

    getSession() {
        const sessionData = sessionStorage.getItem(this.sessionKey) || 
                          localStorage.getItem(this.sessionKey);
        
        if (sessionData) {
            try {
                return JSON.parse(sessionData);
            } catch (e) {
                console.error('Error parsing session data:', e);
                this.clearSession();
            }
        }
        return null;
    }

    isSessionValid(session) {
        if (!session || !session.expires) {
            return false;
        }
        
        const expiryTime = new Date(session.expires);
        const now = new Date();
        
        return now < expiryTime;
    }

    clearSession() {
        sessionStorage.removeItem(this.sessionKey);
        localStorage.removeItem(this.sessionKey);
    }

    generateToken() {
        return 'ics_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    redirectToDashboard() {
        // Check if dashboard exists in same directory
        const dashboardUrl = './index.html';
        
        // Add session token as URL parameter for dashboard to verify
        const session = this.getSession();
        if (session) {
            const url = `${dashboardUrl}?token=${session.token}&role=${encodeURIComponent(session.user.role)}`;
            window.location.href = url;
        } else {
            window.location.href = dashboardUrl;
        }
    }

    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleIcon = document.getElementById('passwordToggle').querySelector('i');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            toggleIcon.className = 'fas fa-eye';
        }
    }

    showLoading(message = 'Loading...') {
        let overlay = document.getElementById('loadingOverlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'loadingOverlay';
            overlay.className = 'loading-overlay';
            overlay.innerHTML = `
                <div class="loading-spinner">
                    <i class="fas fa-spinner fa-spin"></i>
                    <p>${message}</p>
                </div>
            `;
            document.body.appendChild(overlay);
        } else {
            overlay.querySelector('p').textContent = message;
            overlay.style.display = 'flex';
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'none';
        }
    }

    showAlert(message, type = 'info') {
        let container = document.getElementById('alertContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'alertContainer';
            container.className = 'alert-container';
            document.body.appendChild(container);
        }

        const alert = document.createElement('div');
        alert.className = `alert ${type}`;
        alert.innerHTML = `
            <span>${message}</span>
        `;

        container.appendChild(alert);

        // Auto-remove after 4 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.parentNode.removeChild(alert);
            }
        }, 4000);
    }

    loadDemoCredentials() {
        // This method can be used to dynamically update demo credentials
        // Currently credentials are hardcoded, but this allows for future flexibility
        console.log('Demo credentials loaded:', Object.keys(this.demoUsers));
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Utility method to check if user has specific permission
    static hasPermission(permission) {
        const session = JSON.parse(sessionStorage.getItem('ics_security_session') || 
                                 localStorage.getItem('ics_security_session') || '{}');
        
        if (session && session.user && session.user.permissions) {
            return session.user.permissions.includes(permission) || 
                   session.user.permissions.includes('full_access');
        }
        return false;
    }

    // Utility method to get current user info
    static getCurrentUser() {
        const session = JSON.parse(sessionStorage.getItem('ics_security_session') || 
                                 localStorage.getItem('ics_security_session') || '{}');
        return session.user || null;
    }

    // Method to logout
    static logout() {
        const loginManager = new LoginManager();
        loginManager.clearSession();
        window.location.href = './login.html';
    }
}

// Auto-initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new LoginManager();
});

// Global logout function for dashboard use
window.ICSLogin = {
    hasPermission: LoginManager.hasPermission,
    getCurrentUser: LoginManager.getCurrentUser,
    logout: LoginManager.logout
};