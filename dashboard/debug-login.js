// Debug helper for login issues
console.log('🔍 Login Debug Helper Loaded');

// Override the login form to add debugging
document.addEventListener('DOMContentLoaded', function() {
    console.log('🔍 DOM loaded, checking login elements...');
    
    // Check if elements exist
    const username = document.getElementById('username');
    const password = document.getElementById('password');
    const role = document.getElementById('role');
    const form = document.getElementById('loginForm');
    
    console.log('Elements found:', {
        username: !!username,
        password: !!password,
        role: !!role,
        form: !!form
    });
    
    // Add debug listener to form
    if (form) {
        form.addEventListener('submit', function(e) {
            console.log('🔍 Form submitted with values:', {
                username: username?.value,
                password: password?.value,
                role: role?.value
            });
        });
    }
    
    // Add debug listener to credential boxes
    const credentialItems = document.querySelectorAll('.credential-item');
    console.log('🔍 Found credential items:', credentialItems.length);
    
    credentialItems.forEach((item, index) => {
        item.addEventListener('click', function() {
            console.log(`🔍 Clicked credential box ${index}:`, {
                username: item.dataset.username,
                password: item.dataset.password,
                role: item.dataset.role
            });
        });
    });
});