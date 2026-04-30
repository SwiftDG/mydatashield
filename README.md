# MyDataShield

**Automated NDPR Compliance Scanner for Nigerian SMEs**

MyDataShield helps Nigerian businesses automatically check their compliance with the Nigeria Data Protection Regulation (NDPR). Upload your documents, get an instant compliance score, and receive actionable recommendations — no legal expertise required.

🔗 **Live Demo:** [mydatashield.onrender.com](https://mydatashield.onrender.com)

---

## The Problem

Nigeria's Data Protection Regulation (NDPR) requires businesses to handle user data responsibly. Most Nigerian SMEs don't know if they're compliant — and hiring a legal team to find out is expensive.

## The Solution

MyDataShield scans your privacy policies, terms of service, and data handling documents and returns:
- A **compliance score** (0–100%)
- A breakdown of **gaps and violations**
- **Actionable recommendations** to improve your score

---

## Features

- 📄 Document upload and automated analysis
- 📊 Instant NDPR compliance scoring
- ✅ Gap identification and recommendations
- 🔐 Secure user authentication (JWT)
- 👤 Role-based access (Citizens & Organizations)
- 📋 Scan history tracking

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | EJS, HTML, CSS |
| Backend | Node.js, Express.js |
| Database | PostgreSQL |
| Auth | JWT, bcrypt |
| Deployment | Render |

---

## Getting Started

### Prerequisites
- Node.js v18+
- PostgreSQL

### Installation

```bash
git clone https://github.com/SwiftDG/mydatashield.git
cd mydatashield
npm install
```

### Environment Variables

Create a `.env` file in the root:

```env
DB_HOST=your_db_host
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_PORT=5432
JWT_SECRET=your_jwt_secret
SESSION_SECRET=your_session_secret
GMAIL_USER=your_gmail
GMAIL_APP_PASSWORD=your_app_password
```

### Database Setup

```bash
node migrate.js
```

### Run the App

```bash
npm start
```

Visit `http://localhost:3000`

---

## Target Users

- Nigerian startups and SMEs handling user data
- Organizations needing NDPR compliance audits
- Legal and compliance teams

---

## License

MIT

---

*Built by [David Gilbert](https://github.com/SwiftDG)*
