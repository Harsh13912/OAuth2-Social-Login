## 🔧 Setup Instructions

1. Clone the repository
2. Copy `.env.example` to `.env` in both `server/` and `client/`
3. Update `.env` files with your actual credentials:
   - Get Google OAuth from: https://console.cloud.google.com/
   - Get Facebook OAuth from: https://developers.facebook.com/
   - Generate JWT secrets: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
4. Install dependencies and run:
```bash
   cd server && npm install && npm run dev
   cd client && npm install && npm run dev
```