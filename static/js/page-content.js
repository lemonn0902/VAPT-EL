// Additional page content and helper functions

// Quick action buttons for Password Analyzer
function tryWeakPassword() {
    document.getElementById('passwordInput').value = 'abc123';
    analyzePassword();
}

function tryMediumPassword() {
    document.getElementById('passwordInput').value = 'Password1';
    analyzePassword();
}

function tryStrongPassword() {
    document.getElementById('passwordInput').value = 'MyS3cur3P@ssw0rd!2026';
    analyzePassword();
}

// Quick action buttons for Password Hashing
function demonstrateHashing() {
    document.getElementById('hashPasswordInput').value = 'SecurePassword123!';
    hashPassword();
}

// Quick action buttons for Attack Simulation
function tryBruteForceDemo() {
    document.getElementById('brutePasswordInput').value = 'abc';
    runBruteForce();
}

function tryDictionaryDemo() {
    document.getElementById('dictPasswordInput').value = 'password123';
    runDictionaryAttack();
}

// Quick action for Defense System
function demoDefenseSystem() {
    // Enable defense
    document.getElementById('defenseToggle').checked = true;
    toggleDefense();
    
    // Pre-fill test credentials
    document.getElementById('regUsername').value = 'testuser';
    document.getElementById('regPassword').value = 'SecurePass123!';
    
    alert('Defense mechanisms enabled! Register the test user and try multiple failed login attempts to see protection in action.');
}

// Auto-fill failed login
function simulateFailedLogin() {
    document.getElementById('loginUsername').value = 'testuser';
    document.getElementById('loginPassword').value = 'wrongpassword';
}

// Help tooltips
function showHelp(topic) {
    const helpMessages = {
        'strength': 'Enter any password to see its strength rating, entropy calculation, and estimated crack time. Try different password types to see the difference!',
        'hashing': 'See how passwords are transformed into secure hashes. Notice how even a small change in the password creates a completely different hash.',
        'brute': 'Brute force tries every possible combination. Keep passwords short (max 6 chars) for demo purposes as longer ones take too long.',
        'dictionary': 'Dictionary attacks use lists of common passwords. Try: password123, admin, welcome, qwerty, or 123456.',
        'defense': 'Enable defense mechanisms to see how security features prevent attacks. Try logging in with wrong passwords multiple times.',
        'logs': 'View all security events including successful and failed login attempts, attack simulations, and security blocks.'
    };
    
    alert(helpMessages[topic] || 'Help information not available.');
}

// Page-specific initialization
function initializePage(pageName) {
    switch(pageName) {
        case 'dashboard':
            // Update stats on dashboard
            updateStats();
            break;
        case 'logs':
            // Refresh logs when opening logs page
            refreshLogs();
            break;
        case 'defense':
            // Update stats on defense page
            updateStats();
            break;
    }
}

// Export demo data
function exportLogs() {
    fetch('/api/attack-logs')
        .then(response => response.json())
        .then(data => {
            const dataStr = JSON.stringify(data.logs, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'security-logs.json';
            link.click();
        })
        .catch(error => {
            console.error('Error exporting logs:', error);
            alert('Failed to export logs');
        });
}

// Print/Save report
function generateReport() {
    window.print();
}
