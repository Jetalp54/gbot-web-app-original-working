# Quick Fix Guide - 502 Bad Gateway

## 🚨 Immediate Fix (App Will Start Now)

The app can now start **without** `flask_limiter` installed. Rate limiting is optional and will be disabled if the package isn't available.

### Restart the Service:
```bash
sudo systemctl restart gbot
sudo systemctl status gbot
```

The app should now start successfully! ✅

---

## 🔧 Optional: Enable Rate Limiting (Recommended)

To enable rate limiting features (which help prevent 504 errors under high load), install flask_limiter:

```bash
cd /opt/gbot-web-app
source venv/bin/activate
pip install flask-limiter
sudo systemctl restart gbot
```

### What Rate Limiting Does:
- **General API**: 200 requests/day, 50/hour per IP
- **Automation**: 5/minute per IP
- **Mega Upgrade**: 2/hour per IP
- **Uploads**: 10/hour per IP

This helps prevent overload when many machines use the app simultaneously.

---

## 📊 Verify Everything Works

1. **Check Service Status**:
   ```bash
   sudo systemctl status gbot
   ```

2. **Check Logs**:
   ```bash
   sudo journalctl -u gbot -f
   ```

3. **Test Website**:
   - Open `http://ecochains.online/login`
   - Should load without 502 errors

---

## 🎯 Current Status

- ✅ **App starts without flask_limiter** (rate limiting disabled)
- ✅ **All other features work normally**
- ⚠️ **Rate limiting disabled** (optional - install flask_limiter to enable)

---

## 📝 Next Steps

1. **Pull latest code**:
   ```bash
   cd /opt/gbot-web-app
   git pull
   ```

2. **Restart service**:
   ```bash
   sudo systemctl restart gbot
   ```

3. **Verify**:
   ```bash
   sudo journalctl -u gbot -n 50
   ```

The app should now be running! 🎉
