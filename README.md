# Password Security & Credential Attack Detection System

## 🔐 Project Overview

**"Interactive Analysis of Password Security and Credential Attack Detection"**

This is an advanced, educational web application that demonstrates password security vulnerabilities and defense mechanisms through interactive simulations. The project safely simulates credential-based attacks and shows how proper security measures can prevent them.

## 🎯 Problem Statement

Traditional password systems are vulnerable to credential-based attacks such as brute force, dictionary attacks, and credential stuffing. This project demonstrates how weak passwords and poor authentication policies can be exploited, and how proper security mechanisms significantly reduce attack success.

## ✨ Features

### 🔍 1: Password Strength Analyzer
- Real-time password strength assessment with visual indicators
- Entropy calculation and bit strength analysis
- Estimated crack time computation with multiple scenarios
- Character composition analysis (uppercase, lowercase, numbers, symbols)
- Common password detection from database
- Interactive visual strength meter

### 🔑 2: Password Generator
- **NEW!** Generate cryptographically secure random passwords
- Customizable password length (8-64 characters)
- Toggle character types (uppercase, lowercase, numbers, symbols)
- Pronounceable password option for easier memorization
- One-click copy to clipboard
- Real-time strength analysis of generated passwords

### 🗄️ 3: Data Breach Checker
- **NEW!** Check if passwords have been exposed in data breaches
- Simulated breach database with millions of compromised passwords
- Risk assessment and severity indicators
- Educational warnings about password reuse
- Recommendations for compromised passwords

### 🔒 4: Password Storage Simulation
- Demonstrates secure vs. insecure storage methods
- Multiple hashing algorithms comparison (MD5, SHA-256, BCrypt)
- Visual comparison of hash outputs
- Best practices demonstration
- Why BCrypt is recommended for password storage

### 💀 5: Credential Attack Simulation
- **Brute Force Attack**: Systematically tries all combinations
- **Dictionary Attack**: Tests against common password lists
- Safe, controlled attack environment
- Real-time statistics and success rates
- Attack speed and efficiency metrics
- Visual demonstration of attack progression

### 🛡️ 6: Attack Detection & Defense
- Account lockout after failed attempts (configurable threshold)
- Rate limiting (max attempts per time window)
- Login delay mechanisms to slow down attackers
- Real-time security event monitoring
- Test user account system
- Toggle defense mechanisms on/off for comparison

### 📱 7: Two-Factor Authentication (2FA) Demo
- **NEW!** Interactive 2FA/MFA demonstration
- QR code generation for authenticator apps
- TOTP (Time-based One-Time Password) implementation
- Works with Google Authenticator, Authy, Microsoft Authenticator
- Real-time code verification
- Educational explanation of 2FA benefits

### 📋 8: Password Policy Configuration
- **NEW!** Create custom password policies
- Configurable requirements (length, character types, etc.)
- Test passwords against custom policies
- Real-time compliance checking
- Policy violation reporting
- Industry standard policy templates

### 📊 9: Security Event Logs
- Comprehensive attack logging system
- Success/failure tracking with detailed metrics
- Timestamp and IP recording
- Visual log analysis with filtering
- Export logs in JSON format
- Real-time statistics dashboard

### 📥 10: Export & Reporting
- **NEW!** Export security analysis reports
- JSON format with complete statistics
- User account summaries
- Attack log history
- Defense mechanism status
- Downloadable for offline analysis

## 🎨 UI/UX Enhancements

### Modern Design System
- **Glassmorphism effects** with backdrop blur
- **Dark mode support** with toggle button
- **Gradient backgrounds** with animated effects
- **Enhanced animations** (fade-in, slide-up, pulse, glow)
- **Professional color scheme** with accessibility in mind
- **Responsive design** for all screen sizes
- **Interactive hover effects** on all components
- **Smooth transitions** throughout the application

### Visual Components
- Modern card layouts with shadows and borders
- Progress bars with shimmer effects
- Badge system for status indicators
- Toast notifications for user feedback
- Loading overlays with spinners
- Tooltips for additional information
- Icon integration throughout

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Installation Steps

1. **Clone or Download the Project**
   ```bash
   cd VAPT-EL
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**
   ```bash
   python app.py
   ```

4. **Access the Application**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

## 📦 Dependencies

```
Flask==3.0.0
bcrypt==4.1.2
Werkzeug==3.0.1
pyotp==2.9.0
qrcode==7.4.2
Pillow==10.1.0
```

## 🎓 Educational Use Cases

### For Students
- Learn about password security fundamentals
- Understand hashing algorithms and their differences
- See real-world attack simulations
- Practice creating secure passwords
- Understand the importance of 2FA

### For Educators
- Interactive demonstrations for cybersecurity courses
- Visual examples of security concepts
- Safe environment for hands-on learning
- Customizable scenarios for different skill levels

### For Developers
- Reference implementation of security best practices
- Examples of Flask security features
- Password hashing implementation examples
- 2FA integration demonstration

## 🔧 Technical Architecture

### Backend (Flask)
- RESTful API design
- Secure password hashing with BCrypt
- Session management
- TOTP implementation for 2FA
- JSON data persistence
- Error handling and validation

### Frontend
- Modern JavaScript (ES6+)
- Responsive CSS with custom properties
- Fetch API for async requests
- Interactive DOM manipulation
- Chart.js ready integration
- Mobile-first design approach

### Security Features
- No actual user data stored permanently
- All simulations are isolated
- Educational purpose only
- Best practices demonstrated
- XSS and CSRF protection considerations

## 📝 Usage Guide

### Getting Started
1. Start with the **Dashboard** to get an overview
2. Try the **Password Analyzer** to check your passwords
3. Use the **Password Generator** to create secure passwords
4. Check passwords with the **Breach Checker**
5. Learn about hashing in the **Password Hashing** section
6. Run attack simulations in **Attack Simulation**
7. Enable defenses in the **Defense System**
8. Set up **2FA** to understand multi-factor authentication
9. Configure policies in **Password Policy**
10. Review activities in **Security Logs**

### Best Practices Demonstrated
- ✅ Use BCrypt for password hashing
- ✅ Implement account lockout mechanisms
- ✅ Enable rate limiting
- ✅ Use strong password policies
- ✅ Enable two-factor authentication
- ✅ Monitor security events
- ✅ Avoid common passwords
- ✅ Use sufficient password length (12+ characters)
- ✅ Use mix of character types
- ✅ Never reuse passwords

## ⚠️ Important Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This project is designed for:
- Educational demonstrations
- Security awareness training
- Cybersecurity course material
- Password security research

Do NOT use for:
- Illegal activities
- Unauthorized access attempts
- Malicious purposes
- Production authentication systems without proper security review

## 🤝 Contributing

This is an educational project. Suggestions for improvements:
- Additional attack simulation types
- More defense mechanisms
- Enhanced visualizations
- Additional security features
- Improved UI/UX

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

## 🔗 Resources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [BCrypt Documentation](https://pypi.org/project/bcrypt/)

## 👨‍💻 Project Information

**Created for:** Vulnerability Assessment and Penetration Testing (VAPT) Educational Project  
**Year:** 2026  
**Technology Stack:** Python, Flask, HTML5, CSS3, JavaScript  
**Purpose:** Security Education & Awareness

---

**⭐ Star this project if you found it helpful for learning about password security!**
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
