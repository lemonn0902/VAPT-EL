// Utility Functions
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

// Sidebar Toggle Function
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    
    sidebar.classList.toggle('collapsed');
    mainContent.classList.toggle('expanded');
    
    // Save state to localStorage
    const isCollapsed = sidebar.classList.contains('collapsed');
    localStorage.setItem('sidebarCollapsed', isCollapsed);
}

// Initialize sidebar state from localStorage
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    
    if (isCollapsed) {
        sidebar.classList.add('collapsed');
        mainContent.classList.add('expanded');
    }
});

// Navigation System
function navigateTo(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Remove active class from all nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected page
    const pageMap = {
        'dashboard': 'dashboardPage',
        'strength': 'strengthPage',
        'generator': 'generatorPage',
        'breach': 'breachPage',
        'hashing': 'hashingPage',
        'attacks': 'attacksPage',
        'defense': 'defensePage',
        '2fa': '2faPage',
        'policy': 'policyPage',
        'logs': 'logsPage'
    };
    
    const pageId = pageMap[pageName];
    if (pageId) {
        document.getElementById(pageId).classList.add('active');
        
        // Find and activate corresponding nav button
        const navButtons = document.querySelectorAll('.nav-btn');
        const buttonIndex = {
            'dashboard': 0,
            'strength': 1,
            'generator': 2,
            'breach': 3,
            'hashing': 4,
            'attacks': 5,
            'defense': 6,
            '2fa': 7,
            'policy': 8,
            'logs': 9
        }[pageName];
        
        if (navButtons[buttonIndex]) {
            navButtons[buttonIndex].classList.add('active');
        }
        
        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
        
        // Refresh data for specific pages
        if (pageName === 'logs') {
            refreshLogs();
        }
        
        // Update stats when navigating to dashboard or defense
        if (pageName === 'dashboard' || pageName === 'defense') {
            updateStats();
        }
    }
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}

function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    if (tabName === 'brute') {
        document.getElementById('bruteTab').classList.add('active');
        document.querySelector('.tab-btn:nth-child(1)').classList.add('active');
    } else if (tabName === 'dictionary') {
        document.getElementById('dictionaryTab').classList.add('active');
        document.querySelector('.tab-btn:nth-child(2)').classList.add('active');
    } else if (tabName === 'c2c') {
        document.getElementById('c2cTab').classList.add('active');
        document.querySelector('.tab-btn:nth-child(3)').classList.add('active');
    }
}

// Step 1: Password Strength Analyzer
async function analyzePassword() {
    const password = document.getElementById('passwordInput').value;
    
    if (!password) {
        alert('Please enter a password to analyze');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/password-strength', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('strengthResult');
        resultDiv.style.display = 'block';
        
        // Update strength bar
        const strengthBar = document.getElementById('strengthBar');
        strengthBar.className = 'strength-bar ' + data.strength.toLowerCase();
        
        // Update strength text
        const strengthText = document.getElementById('strengthText');
        strengthText.textContent = data.strength;
        strengthText.className = 'badge ' + data.color;
        
        // Update details
        document.getElementById('crackTime').textContent = data.crack_time;
        document.getElementById('passwordLength').textContent = data.length;
        document.getElementById('entropy').textContent = data.entropy;
        
        // Update checklist
        updateCheckItem('checkUpper', data.has_upper);
        updateCheckItem('checkLower', data.has_lower);
        updateCheckItem('checkDigit', data.has_digit);
        updateCheckItem('checkSpecial', data.has_special);
        updateCheckItem('checkCommon', !data.is_common);
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while analyzing the password');
    } finally {
        hideLoading();
    }
}

function updateCheckItem(id, isValid) {
    const item = document.getElementById(id);
    const icon = item.querySelector('i');
    
    if (isValid) {
        item.classList.add('valid');
        item.classList.remove('invalid');
        icon.className = 'fas fa-check';
    } else {
        item.classList.add('invalid');
        item.classList.remove('valid');
        icon.className = 'fas fa-times';
    }
}

// Step 2: Password Hashing
async function hashPassword() {
    const password = document.getElementById('hashPasswordInput').value;
    
    if (!password) {
        alert('Please enter a password to hash');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/hash-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('hashResult');
        resultDiv.style.display = 'block';
        
        document.getElementById('plainText').textContent = data.plain;
        document.getElementById('md5Hash').textContent = data.md5;
        document.getElementById('sha256Hash').textContent = data.sha256;
        document.getElementById('bcryptHash').textContent = data.bcrypt;
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while hashing the password');
    } finally {
        hideLoading();
    }
}

// Step 3: Attack Simulations
async function runBruteForce() {
    const password = document.getElementById('brutePasswordInput').value;
    
    if (!password) {
        alert('Please enter a target password');
        return;
    }
    
    if (password.length > 6) {
        alert('For demonstration purposes, please use a password of 6 characters or less');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/brute-force', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password, max_length: 6 })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('bruteResult');
        resultDiv.style.display = 'block';
        
        if (data.success) {
            resultDiv.innerHTML = `
                <div class="alert error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>⚠️ Password Cracked!</strong>
                        <p>The password "${data.cracked_password}" was successfully cracked.</p>
                    </div>
                </div>
                <div class="result-grid">
                    <div class="result-item">
                        <strong>Attempts:</strong>
                        <span>${data.attempts.toLocaleString()}</span>
                    </div>
                    <div class="result-item">
                        <strong>Time Taken:</strong>
                        <span>${data.time}s</span>
                    </div>
                    <div class="result-item">
                        <strong>Attack Rate:</strong>
                        <span>${data.rate.toLocaleString()}/sec</span>
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="alert success">
                    <i class="fas fa-shield-alt"></i>
                    <div>
                        <strong>✅ Password Secure!</strong>
                        <p>Brute force attack failed after ${data.attempts.toLocaleString()} attempts.</p>
                    </div>
                </div>
                <div class="result-grid">
                    <div class="result-item">
                        <strong>Attempts:</strong>
                        <span>${data.attempts.toLocaleString()}</span>
                    </div>
                    <div class="result-item">
                        <strong>Time Taken:</strong>
                        <span>${data.time}s</span>
                    </div>
                    <div class="result-item">
                        <strong>Attack Rate:</strong>
                        <span>${data.rate.toLocaleString()}/sec</span>
                    </div>
                </div>
            `;
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during the brute force attack');
    } finally {
        hideLoading();
    }
}

async function runDictionaryAttack() {
    const password = document.getElementById('dictPasswordInput').value;
    
    if (!password) {
        alert('Please enter a target password');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/dictionary-attack', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('dictResult');
        resultDiv.style.display = 'block';
        
        if (data.success) {
            resultDiv.innerHTML = `
                <div class="alert error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>⚠️ Weak Password Detected!</strong>
                        <p>Password "${data.cracked_password}" found in common password dictionary.</p>
                    </div>
                </div>
                <div class="result-grid">
                    <div class="result-item">
                        <strong>Dictionary Size:</strong>
                        <span>${data.dictionary_size.toLocaleString()}</span>
                    </div>
                    <div class="result-item">
                        <strong>Attempts:</strong>
                        <span>${data.attempts.toLocaleString()}</span>
                    </div>
                    <div class="result-item">
                        <strong>Time Taken:</strong>
                        <span>${data.time}s</span>
                    </div>
                </div>
                <div class="info-text">
                    <i class="fas fa-info-circle"></i>
                    <p>This password is vulnerable because it appears in common password lists used by attackers.</p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="alert success">
                    <i class="fas fa-shield-alt"></i>
                    <div>
                        <strong>✅ Password Not in Dictionary!</strong>
                        <p>Dictionary attack failed. Password not found in common wordlist.</p>
                    </div>
                </div>
                <div class="result-grid">
                    <div class="result-item">
                        <strong>Dictionary Size:</strong>
                        <span>${data.dictionary_size.toLocaleString()}</span>
                    </div>
                    <div class="result-item">
                        <strong>Attempts:</strong>
                        <span>${data.attempts.toLocaleString()}</span>
                    </div>
                    <div class="result-item">
                        <strong>Time Taken:</strong>
                        <span>${data.time}s</span>
                    </div>
                </div>
                <div class="info-text">
                    <i class="fas fa-info-circle"></i>
                    <p>However, brute force attacks could still crack it given enough time and computing power.</p>
                </div>
            `;
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during the dictionary attack');
    } finally {
        hideLoading();
    }
}

// Step 4: Defense Mechanisms
async function toggleDefense() {
    const checkbox = document.getElementById('defenseToggle');
    const enabled = checkbox.checked;
    
    try {
        const response = await fetch('/api/toggle-defense', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled })
        });
        
        const data = await response.json();
        
        const statusText = document.getElementById('defenseStatus');
        if (enabled) {
            statusText.innerHTML = 'Defense Mechanisms: <strong style="color: #10b981;">ENABLED</strong>';
        } else {
            statusText.innerHTML = 'Defense Mechanisms: <strong style="color: #ef4444;">DISABLED</strong>';
        }
        
        // Refresh stats
        updateStats();
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while toggling defense mechanisms');
    }
}

async function registerUser() {
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    
    if (!username || !password) {
        alert('Please enter both username and password');
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('✅ ' + data.message);
            document.getElementById('regUsername').value = '';
            document.getElementById('regPassword').value = '';
            updateStats();
        } else {
            alert('❌ ' + data.error);
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during registration');
    }
}

async function testLogin() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!username || !password) {
        alert('Please enter both username and password');
        return;
    }
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        const resultDiv = document.getElementById('loginResult');
        resultDiv.style.display = 'block';
        
        if (data.success) {
            resultDiv.innerHTML = `
                <div class="alert success">
                    <i class="fas fa-check-circle"></i>
                    <div>
                        <strong>✅ Login Successful</strong>
                        <p>${data.message}</p>
                    </div>
                </div>
            `;
        } else {
            const alertClass = data.blocked ? 'error' : 'warning';
            const icon = data.blocked ? 'fa-ban' : 'fa-exclamation-triangle';
            resultDiv.innerHTML = `
                <div class="alert ${alertClass}">
                    <i class="fas ${icon}"></i>
                    <div>
                        <strong>${data.blocked ? '🚫 Blocked' : '⚠️ Failed'}</strong>
                        <p>${data.message}</p>
                    </div>
                </div>
            `;
        }
        
        // Update stats and refresh logs
        updateStats();
        refreshLogs();
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during login');
    }
}

async function resetAccounts() {
    if (!confirm('Are you sure you want to reset all accounts?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/reset-accounts', {
            method: 'POST'
        });
        
        const data = await response.json();
        alert('✅ ' + data.message);
        
        // Clear inputs
        document.getElementById('regUsername').value = '';
        document.getElementById('regPassword').value = '';
        document.getElementById('loginUsername').value = '';
        document.getElementById('loginPassword').value = '';
        document.getElementById('loginResult').style.display = 'none';
        
        updateStats();
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while resetting accounts');
    }
}

// Step 5: Logs
async function refreshLogs() {
    try {
        const response = await fetch('/api/attack-logs');
        const data = await response.json();
        
        const logsContainer = document.getElementById('logsContainer');
        
        if (data.logs.length === 0) {
            logsContainer.innerHTML = '<p class="info-text">No security events logged yet.</p>';
            return;
        }
        
        let logsHTML = '';
        data.logs.reverse().forEach(log => {
            const logClass = log.success ? 'success' : 'failure';
            const badgeClass = log.success ? 'success' : 'failure';
            const icon = log.success ? 'fa-check-circle' : 'fa-times-circle';
            const timestamp = new Date(log.timestamp).toLocaleString();
            
            logsHTML += `
                <div class="log-entry ${logClass}">
                    <div class="log-timestamp">
                        <i class="fas fa-clock"></i> ${timestamp}
                    </div>
                    <div class="log-details">
                        <strong><i class="fas ${icon}"></i> ${log.type}</strong>
                        <small>User: ${log.username} | IP: ${log.source_ip} | ${log.details}</small>
                    </div>
                    <span class="log-badge ${badgeClass}">${log.success ? 'Success' : 'Failed'}</span>
                </div>
            `;
        });
        
        logsContainer.innerHTML = logsHTML;
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while fetching logs');
    }
}

async function clearLogs() {
    if (!confirm('Are you sure you want to clear all logs?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/clear-logs', {
            method: 'POST'
        });
        
        const data = await response.json();
        alert('✅ ' + data.message);
        refreshLogs();
        updateStats();
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while clearing logs');
    }
}

// Update Stats
async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        document.getElementById('totalUsers').textContent = data.total_users;
        document.getElementById('totalAttempts').textContent = data.total_login_attempts;
        document.getElementById('lockedAccounts').textContent = data.locked_accounts;
        document.getElementById('totalLogs').textContent = data.total_logs;
        
    } catch (error) {
        console.error('Error:', error);
    }
}

// Dark Mode Toggle
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', newTheme);
    
    const icon = document.getElementById('themeIcon');
    icon.className = newTheme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
    
    localStorage.setItem('theme', newTheme);
}

// Password Generator
function updateLengthDisplay(value) {
    document.getElementById('lengthValue').textContent = value;
}

async function generatePassword() {
    const length = document.getElementById('passwordLength').value;
    const include_upper = document.getElementById('includeUpper').checked;
    const include_lower = document.getElementById('includeLower').checked;
    const include_numbers = document.getElementById('includeNumbers').checked;
    const include_symbols = document.getElementById('includeSymbols').checked;
    const pronounceable = document.getElementById('pronounceable').checked;
    
    showLoading();
    
    try {
        const response = await fetch('/api/generate-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                length: parseInt(length),
                include_upper,
                include_lower,
                include_numbers,
                include_symbols,
                pronounceable
            })
        });
        
        const data = await response.json();
        
        // Display generated password
        const resultDiv = document.getElementById('generatedPassword');
        resultDiv.style.display = 'block';
        document.getElementById('generatedPasswordText').value = data.password;
        
        // Display strength info
        const strengthDiv = document.getElementById('generatedStrength');
        strengthDiv.innerHTML = `
            <div class="result-item">
                <strong>Strength:</strong>
                <span class="badge badge-${data.strength.color}">${data.strength.strength}</span>
            </div>
            <div class="result-item">
                <strong>Entropy:</strong>
                <span>${data.strength.entropy} bits</span>
            </div>
            <div class="result-item">
                <strong>Length:</strong>
                <span>${data.strength.length} characters</span>
            </div>
        `;
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while generating the password');
    } finally {
        hideLoading();
    }
}

function copyPassword() {
    const passwordField = document.getElementById('generatedPasswordText');
    passwordField.select();
    document.execCommand('copy');
    
    // Show feedback
    const btn = event.target.closest('button');
    const originalHTML = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
    btn.classList.add('btn-success');
    
    setTimeout(() => {
        btn.innerHTML = originalHTML;
        btn.classList.remove('btn-success');
    }, 2000);
}

// Breach Checker
async function checkBreach() {
    const password = document.getElementById('breachPasswordInput').value;
    
    if (!password) {
        alert('Please enter a password to check');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/check-breach', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('breachResult');
        resultDiv.style.display = 'block';
        
        if (data.is_breached) {
            resultDiv.innerHTML = `
                <div class="alert error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>⚠️ PASSWORD COMPROMISED!</strong>
                        <p>${data.message}</p>
                        <p><strong>Recommendation:</strong> Choose a different password immediately!</p>
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="alert success">
                    <i class="fas fa-check-circle"></i>
                    <div>
                        <strong>✓ Password Not Found in Breaches</strong>
                        <p>${data.message}</p>
                        <p>This password has not been found in our breach database.</p>
                    </div>
                </div>
            `;
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while checking the breach database');
    } finally {
        hideLoading();
    }
}

// 2FA Demo
let current2FASecret = '';

async function setup2FA() {
    const username = document.getElementById('2faUsername').value;
    
    if (!username) {
        alert('Please enter a username or email');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/2fa/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });
        
        const data = await response.json();
        
        // Display QR code
        const qrSection = document.getElementById('qrCodeSection');
        qrSection.style.display = 'block';
        
        document.getElementById('qrCodeImage').src = data.qr_code;
        document.getElementById('secretKey').textContent = data.secret;
        current2FASecret = data.secret;
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while generating 2FA');
    } finally {
        hideLoading();
    }
}

function copySecret() {
    const secretText = document.getElementById('secretKey').textContent;
    navigator.clipboard.writeText(secretText);
    
    // Show feedback
    const btn = event.target.closest('button');
    const originalHTML = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
    
    setTimeout(() => {
        btn.innerHTML = originalHTML;
    }, 2000);
}

async function verify2FA() {
    const code = document.getElementById('2faCode').value;
    
    if (!code || code.length !== 6) {
        alert('Please enter a valid 6-digit code');
        return;
    }
    
    if (!current2FASecret) {
        alert('Please setup 2FA first');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/2fa/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secret: current2FASecret,
                code: code
            })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('2faVerifyResult');
        resultDiv.style.display = 'block';
        
        if (data.valid) {
            resultDiv.innerHTML = `
                <div class="alert success">
                    <i class="fas fa-check-circle"></i>
                    <div>
                        <strong>✓ Code Verified Successfully!</strong>
                        <p>Your 2FA setup is working correctly. This adds an extra layer of security to your account.</p>
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="alert error">
                    <i class="fas fa-times-circle"></i>
                    <div>
                        <strong>✗ Invalid Code</strong>
                        <p>The code you entered is incorrect or has expired. Please try again.</p>
                    </div>
                </div>
            `;
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while verifying the code');
    } finally {
        hideLoading();
    }
}

// Password Policy
function updatePolicyDisplay() {
    document.getElementById('minLengthValue').textContent = document.getElementById('minLength').value;
    document.getElementById('maxLengthValue').textContent = document.getElementById('maxLength').value;
}

async function checkPolicy() {
    const password = document.getElementById('policyPasswordInput').value;
    
    if (!password) {
        alert('Please enter a password to test');
        return;
    }
    
    const policy = {
        min_length: parseInt(document.getElementById('minLength').value),
        max_length: parseInt(document.getElementById('maxLength').value),
        require_uppercase: document.getElementById('requireUpper').checked,
        require_lowercase: document.getElementById('requireLower').checked,
        require_numbers: document.getElementById('requireNumbers').checked,
        require_special: document.getElementById('requireSpecial').checked,
        no_common_passwords: document.getElementById('noCommonPasswords').checked,
        no_repeated_chars: document.getElementById('noRepeatedChars').checked,
        no_sequential: document.getElementById('noSequential').checked
    };
    
    showLoading();
    
    try {
        const response = await fetch('/api/password-policy/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password, policy })
        });
        
        const data = await response.json();
        
        // Display results
        const resultDiv = document.getElementById('policyResult');
        resultDiv.style.display = 'block';
        
        let html = `
            <div class="alert ${data.compliant ? 'success' : 'error'}">
                <i class="fas fa-${data.compliant ? 'check-circle' : 'times-circle'}"></i>
                <div>
                    <strong>${data.compliant ? '✓ Password Complies with Policy' : '✗ Password Violates Policy'}</strong>
                    <p>Compliance Score: ${Math.round(data.score)}%</p>
                </div>
            </div>
            
            ${data.passed.length > 0 ? `
                <h4 style="color: var(--success-color); margin-top: 1rem;">
                    <i class="fas fa-check"></i> Passed Requirements:
                </h4>
                <ul class="checklist">
                    ${data.passed.map(item => `<li class="check-item valid"><i class="fas fa-check"></i> ${item}</li>`).join('')}
                </ul>
            ` : ''}
            
            ${data.violations.length > 0 ? `
                <h4 style="color: var(--danger-color); margin-top: 1rem;">
                    <i class="fas fa-times"></i> Violations:
                </h4>
                <ul class="checklist">
                    ${data.violations.map(item => `<li class="check-item invalid"><i class="fas fa-times"></i> ${item}</li>`).join('')}
                </ul>
            ` : ''}
        `;
        
        resultDiv.innerHTML = html;
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while checking the policy');
    } finally {
        hideLoading();
    }
}

// Export Logs
async function exportLogs() {
    try {
        const response = await fetch('/api/export/json');
        const data = await response.json();
        
        // Create download
        const dataStr = JSON.stringify(data, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `security-report-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        alert('Security report exported successfully!');
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while exporting the logs');
    }
}

// Computer-to-Computer Attack Functions
function tryC2CDemo() {
    document.getElementById('targetIPInput').value = '192.168.1.100';
    document.getElementById('targetPortInput').value = '80';
    runC2CAttack();
}

async function runC2CAttack() {
    const targetIP = document.getElementById('targetIPInput').value.trim();
    const targetPort = document.getElementById('targetPortInput').value.trim();
    
    if (!targetIP || !targetPort) {
        alert('Please enter both target IP and port');
        return;
    }
    
    const port = parseInt(targetPort);
    if (isNaN(port) || port < 1 || port > 65535) {
        alert('Please enter a valid port (1-65535)');
        return;
    }
    
    showLoading();
    try {
        const response = await fetch('/api/c2c-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_ip: targetIP, target_port: port })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            alert('❌ ' + (data.error || 'Attack simulation failed'));
            return;
        }
        
        let resultHTML = '<h4><i class="fas fa-network-wired"></i> Computer-to-Computer Attack Simulation</h4>';
        
        // Overall Result
        const resultStatus = data.success ? 
            '<span style="color: #ef4444;"><i class="fas fa-check-circle"></i> FULL COMPROMISE</span>' : 
            '<span style="color: #10b981;"><i class="fas fa-shield-alt"></i> ATTACK BLOCKED</span>';
        
        resultHTML += `
            <div style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; margin: 10px 0; border-left: 4px solid ${data.success ? '#ef4444' : '#10b981'};">
                <strong>Overall Result:</strong> ${resultStatus}
                <div style="margin-top: 8px; font-size: 0.9em;">
                    <span><strong>Target:</strong> ${data.target_ip}:${data.target_port}</span> | 
                    <span><strong>Total Time:</strong> ${data.total_time}s</span>
                </div>
            </div>
        `;
        
        // Attack Phases Breakdown
        resultHTML += '<h5 style="margin-top: 15px;">Attack Phases:</h5>';
        
        if (data.phases && Array.isArray(data.phases)) {
            data.phases.forEach((phase, index) => {
                let phaseColor = '#666';
                let phaseIcon = '<i class="fas fa-hourglass-half"></i>';
                
                if (phase.status === 'Success' || phase.success === true) {
                    phaseColor = '#ef4444';
                    phaseIcon = '<i class="fas fa-check-circle" style="color: #ef4444;"></i>';
                } else if (phase.status === 'Failed' || phase.status === 'Closed/Filtered') {
                    phaseColor = '#10b981';
                    phaseIcon = '<i class="fas fa-times-circle" style="color: #10b981;"></i>';
                } else if (phase.status === 'Open') {
                    phaseColor = '#f59e0b';
                    phaseIcon = '<i class="fas fa-exclamation-circle" style="color: #f59e0b;"></i>';
                }
                
                resultHTML += `
                    <div style="background: rgba(0,0,0,0.15); padding: 10px; margin: 8px 0; border-radius: 4px; border-left: 3px solid ${phaseColor};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <strong>${phaseIcon} ${index + 1}. ${phase.phase}</strong>
                                <div style="font-size: 0.85em; margin-top: 4px; color: #aaa;">
                                    ${phase.details || phase.service || phase.service_detected || ''}
                                </div>
                            </div>
                            <div style="text-align: right; font-size: 0.85em;">
                                <div><strong>${phase.time}s</strong></div>
                                ${phase.status ? `<div>${phase.status}</div>` : ''}
                            </div>
                        </div>
                    </div>
                `;
            });
        }
        
        // Service Detected
        if (data.service_detected) {
            resultHTML += `
                <div style="background: rgba(0,0,0,0.2); padding: 10px; margin: 10px 0; border-radius: 4px;">
                    <strong>Service Detected:</strong> ${data.service_detected}
                </div>
            `;
        }
        
        // Educational Notes
        resultHTML += `
            <div class="info-text" style="margin-top: 15px;">
                <i class="fas fa-graduation-cap"></i>
                <p><strong>Educational Note:</strong> This is a 100% simulated attack. No real network connections were made. All results are randomized.</p>
                <p><strong>What you learned:</strong> A real attack would involve reconnaissance, port scanning, service enumeration, vulnerability detection, and exploitation. This demo shows each phase with realistic timing and outcomes.</p>
            </div>
        `;
        
        document.getElementById('c2cResult').innerHTML = resultHTML;
        document.getElementById('c2cResult').style.display = 'block';
        
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during the C2C attack simulation');
    } finally {
        hideLoading();
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateStats();
    
    // Auto-refresh stats every 30 seconds (reduced from 5s to avoid rate limiting)
    setInterval(updateStats, 30000);
    
    // Load theme from localStorage
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.className = savedTheme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
    }
});

