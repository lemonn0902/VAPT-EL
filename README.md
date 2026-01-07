# Password Security & Credential Attack Detection System

## 🔐 Project Overview

**"Interactive Analysis of Password Security and Credential Attack Detection"**

This is an educational web application that demonstrates password security vulnerabilities and defense mechanisms through interactive simulations. The project safely simulates credential-based attacks and shows how proper security measures can prevent them.

## 🎯 Problem Statement

Traditional password systems are vulnerable to credential-based attacks such as brute force, dictionary attacks, and credential stuffing. This project demonstrates how weak passwords and poor authentication policies can be exploited, and how proper security mechanisms significantly reduce attack success.

## ✨ Features

### 1: Password Strength Analyzer
- Real-time password strength assessment
- Entropy calculation
- Estimated crack time computation
- Character composition analysis
- Common password detection

### 2: Password Storage Simulation
- Demonstrates secure vs. insecure storage
- Multiple hashing algorithms (MD5, SHA-256, BCrypt)
- Visual comparison of hash outputs
- Best practices demonstration

### 3: Credential Attack Simulation
- **Brute Force Attack**: Systematically tries all combinations
- **Dictionary Attack**: Tests against common password lists
- Safe, controlled attack environment
- Real-time statistics and success rates

### 4: Attack Detection & Defense
- Account lockout after failed attempts
- Rate limiting (max attempts per time window)
- Login delay mechanisms
- Real-time security event monitoring
- Test user account system

### 5: Security Event Logs
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


## 🛠️ Technical Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript
- **Security**: bcrypt, hashlib
- **Features**: RESTful API, Real-time updates


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


---

**Remember**: Always practice ethical security testing and obtain proper authorization before testing any systems.
