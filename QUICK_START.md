# 🚀 APIShield Quick Start Guide

## **One-Command Setup & Run**

### **For Linux/macOS:**
```bash
# Make script executable and run
chmod +x install_and_run.sh
./install_and_run.sh
```

### **For Windows:**
```cmd
# Run as Administrator
install_and_run.bat
```

## **What This Does:**

1. **🔧 Installs all dependencies** (Python, Java, Redis, security tools)
2. **🛠️ Sets up security tools** (ZAP, Nuclei, SQLMap, SSRFMap, XSStrike)
3. **⚙️ Creates configuration files** with proper settings
4. **🚀 Starts the application** automatically
5. **🌐 Opens dashboard** at `http://localhost:5001`

## **Default Login:**
- **Username:** `admin`
- **Password:** `secure_password_change_this`

## **Alternative Options:**

### **Install Only:**
```bash
# Linux/macOS
./install_and_run.sh install

# Windows
install_and_run.bat install
```

### **Run Only (after installation):**
```bash
# Linux/macOS
./install_and_run.sh run

# Windows
install_and_run.bat run
```

## **Manual Start/Stop:**

### **Start:**
```bash
# Linux/macOS
./start.sh

# Windows
start.bat
```

### **Stop:**
```bash
# Linux/macOS
./stop.sh

# Windows
stop.bat
```

## **Next Steps:**

1. **Access Dashboard:** `http://localhost:5001`
2. **Change Password:** Modify `config.py` or `.env`
3. **Configure APIs:** Update API endpoints in config
4. **Enable Monitoring:** Go to Real-Time Monitoring section
5. **Establish Baseline:** Click "Establish Baseline" button

## **Need Help?**

- **Full Documentation:** `README.md`
- **Troubleshooting:** Check logs in `app.log` and `celery.log`
- **Issues:** Check the troubleshooting section in README.md

---

**🎉 That's it! You're ready to secure your APIs!**
