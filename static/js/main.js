// Utility Functions
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

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
        'hashing': 'hashingPage',
        'attacks': 'attacksPage',
        'defense': 'defensePage',
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
            'hashing': 2,
            'attacks': 3,
            'defense': 4,
            'logs': 5
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

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateStats();
    
    // Auto-refresh stats every 5 seconds
    setInterval(updateStats, 5000);
});
