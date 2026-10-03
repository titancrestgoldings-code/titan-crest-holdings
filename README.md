# Titan Crest Holdings — UK Portal Backend Starter

This is a working local prototype with:
- Express server
- SQLite database
- Password hashing with bcrypt
- Session-based login/logout
- Investor registration
- Investor dashboard
- Demo investment records in GBP

## Run
1. Install Node.js LTS.
2. Open this folder in a terminal.
3. Run `npm install`
4. Set a strong `SESSION_SECRET` environment variable.
5. Run `npm start`
6. Open http://localhost:3000

## Important
This prototype deliberately does NOT process real deposits, withdrawals or investment transactions. Before using a real UK investment service, obtain the required regulatory/legal advice and permissions, and replace the demo data flow with a compliant architecture.

For a production deployment, use HTTPS, a managed database, secure secrets, email verification, password reset, MFA, rate limiting, audit logging, backups, role-based access controls and a proper compliance/KYC/AML workflow.
