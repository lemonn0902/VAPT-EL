# Password Security & Credential Attack Detection System

## 🔐 Project Overview

**"Interactive Analysis of Password Security and Credential Attack Detection"**

This is an educational web application that demonstrates password security vulnerabilities and defense mechanisms through interactive simulations. The project safely simulates credential-based attacks and shows how proper security measures can prevent them.

## 🎯 Problem Statement

Traditional password systems are vulnerable to credential-based attacks such as brute force, dictionary attacks, and credential stuffing. This project demonstrates how weak passwords and poor authentication policies can be exploited, and how proper security mechanisms significantly reduce attack success.

## ✨ Features

### Step 1: Password Strength Analyzer
- Real-time password strength assessment
- Entropy calculation
- Estimated crack time computation
- Character composition analysis
- Common password detection

### Step 2: Password Storage Simulation
- Demonstrates secure vs. insecure storage
- Multiple hashing algorithms (MD5, SHA-256, BCrypt)
- Visual comparison of hash outputs
- Best practices demonstration

### Step 3: Credential Attack Simulation
- **Brute Force Attack**: Systematically tries all combinations
- **Dictionary Attack**: Tests against common password lists
- Safe, controlled attack environment
- Real-time statistics and success rates

### Step 4: Attack Detection & Defense
- Account lockout after failed attempts
- Rate limiting (max attempts per time window)
- Login delay mechanisms
- Real-time security event monitoring
- Test user account system

### Step 5: Security Event Logs
- Comprehensive attack logging
- Success/failure tracking
- Timestamp and IP recording
- Visual log analysis

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. **Clone or navigate to the project directory**
```bash
cd vapt-el
```

2. **Install required dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Open your browser**
Navigate to: `http://127.0.0.1:5000`

## 📖 Usage Guide

### Navigation System

The application features a **multi-page navigation system** with six main sections:

1. **Dashboard** - Overview and quick access to all features
2. **Password Analyzer** - Real-time password strength testing
3. **Password Hashing** - Secure storage demonstration
4. **Attack Simulation** - Brute force and dictionary attacks
5. **Defense System** - Security mechanisms testing
6. **Security Logs** - Event monitoring and analysis

#### Quick Navigation
- Click any button in the top navigation bar to switch pages
- Use "Previous" and "Next" buttons at the bottom of each page
- Click "Back to Dashboard" to return to the home page

### Quick Action Buttons

Each page includes **Quick Action** buttons for instant demonstrations:

- **Password Analyzer**: Try Weak/Medium/Strong passwords instantly
- **Password Hashing**: Quick demo with pre-filled password
- **Attack Simulation**: One-click demo for brute force and dictionary attacks
- **Defense System**: Quick setup for defense demonstration
- **Security Logs**: Export logs as JSON file

### For Demonstration/Evaluation:

1. **Start with Password Analysis**
   - Enter different passwords (weak, medium, strong)
   - Observe strength metrics and crack time estimates
   - Example passwords to try:
     - Weak: `abc123`
     - Medium: `Password1`
     - Strong: `MyS3cur3P@ssw0rd!2026`

2. **Show Password Hashing**
   - Enter a password
   - Compare plain text vs. hashed outputs
   - Explain why BCrypt is recommended

3. **Run Attack Simulations**
   - **Brute Force**: Try a short password like `abc` or `123`
   - **Dictionary Attack**: Try common passwords like `password123`, `admin`, `welcome`
   - Show how weak passwords fail quickly

4. **Enable Defense Mechanisms**
   - Toggle defense ON
   - Register a test user
   - Try multiple failed login attempts
   - Show account lockout and rate limiting in action

5. **Review Security Logs**
   - Display all attack attempts
   - Show blocked vs. successful attempts
   - Analyze patterns

## 🎥 Demo Flow (5-7 minutes)

**NEW Multi-Page Navigation Flow:**

1. **Dashboard Introduction** (30 sec)
   - Show the welcome page with all feature cards
   - Explain the 6 interactive sections
   - Click on Password Analyzer

2. **Password Analyzer** (1 min)
   - Use "Try Weak Password" button → show instant crack time
   - Use "Try Strong Password" button → show years to crack
   - Explain entropy and strength metrics
   - Click "Next: Password Hashing"

3. **Hashing Demo** (1 min)
   - Click "Quick Demo" button
   - Compare plain text vs. hashed outputs
   - Explain why BCrypt is recommended
   - Click "Next: Attack Simulation"

4. **Attack WITHOUT Defense** (2 min)
   - Switch to "Brute Force" tab, click "Quick Demo"
   - Switch to "Dictionary Attack" tab, click "Quick Demo"
   - Show how weak passwords fail quickly
   - Click "Next: Defense System"

5. **Attack WITH Defense** (2 min)
   - Click "Quick Setup Demo" button
   - Register the pre-filled test user
   - Attempt multiple failed logins → BLOCKED
   - Show account lockout and rate limiting
   - Click "Next: Security Logs"

6. **Results Analysis** (1 min)
   - Click "Refresh Logs" to see all events
   - Show blocked vs. successful attempts
   - Click "Export Logs" to download data
   - Return to Dashboard

**Pro Tip**: Use the navigation bar at the top to jump between sections during Q&A!

## 🛠️ Technical Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript
- **Security**: bcrypt, hashlib
- **Features**: RESTful API, Real-time updates

## 📊 What Makes This Stand Out

✅ **Multi-page navigation** - Professional web app structure with intuitive flow  
✅ **Quick action buttons** - Instant demonstrations for faster presentations  
✅ **Hands-on demonstration** - Not just theory, actual working simulations  
✅ **Both attack + defense shown** - Complete security picture  
✅ **No illegal hacking** - Controlled, safe environment  
✅ **Real-world relevance** - Addresses actual security concerns  
✅ **Easy to explain** - Visual, intuitive interface  
✅ **Professional UI** - Modern, responsive design with smooth transitions  
✅ **Comprehensive logging** - Detailed event tracking with export functionality  
✅ **Educational tooltips** - Help and tips integrated throughout  

## ⚠️ Important Notes

- **Educational Purpose Only**: This tool is for learning and demonstration
- **Controlled Environment**: All attacks are simulated safely
- **No External Targets**: Never use against real systems without permission
- **Limited Scope**: Attack simulations are simplified for demonstration

## 📝 Project Structure

```
vapt-el/
│
├── app.py                  # Flask backend application
├── requirements.txt        # Python dependencies
├── wordlist.txt           # Common passwords for dictionary attack
│
├── templates/
│   └── index.html         # Main web interface
│
└── static/
    ├── css/
    │   └── style.css      # Styling
    └── js/
        └── main.js        # Frontend functionality
```

## 🎓 Learning Outcomes

Students/Viewers will understand:
- How password strength affects security
- Why proper password storage is critical
- How credential attacks work
- Effectiveness of defense mechanisms
- Real-world security best practices

## 🔧 Troubleshooting

**Issue**: Port 5000 already in use  
**Solution**: Change port in app.py: `app.run(debug=True, port=5001)`

**Issue**: bcrypt installation fails  
**Solution**: Install build tools or use pre-built wheels

**Issue**: Static files not loading  
**Solution**: Ensure folder structure matches exactly

## 📄 License

This project is for educational purposes. Free to use and modify for learning.

## 👨‍💻 Developer

Created for VAPT (Vulnerability Assessment and Penetration Testing) educational demonstration.

---

**Remember**: Always practice ethical security testing and obtain proper authorization before testing any systems.
