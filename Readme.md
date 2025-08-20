---

# OTP-Based Authentication System

A secure and production-ready **OTP (One-Time Password) based authentication system** built with **Node.js, Express, Prisma, Arcjet, and JWT**.
This project enables email-based user authentication without passwords, using **time-limited OTPs**, **refresh tokens**, and **secure cookies**.

---

## 🚀 Features

* **OTP-based login** (no password required)
* **Email validation with Arcjet** (blocks disposable/invalid emails)
* **Rate limiting for OTP requests** (prevents abuse)
* **OTP expiration and attempt limits** (max 3 attempts per code, 10 min expiry)
* **JWT-based authentication** (Access & Refresh tokens)
* **Secure cookie storage** (httpOnly, sameSite, secure in production)
* **Resend OTP** with cooldown
* **Refresh Access Token** using Refresh Token
* **Logout** (invalidates refresh token in DB)

---

## 🛠 Tech Stack

* **Node.js** (v18+)
* **Express** (v5)
* **Prisma ORM** (PostgreSQL/MySQL/SQLite)
* **JWT** (Access & Refresh tokens)
* **Arcjet** (email validation)
* **Bcrypt** (OTP hashing)
* **Nodemailer** (email delivery)
* **dotenv** (env management)

---

## 📂 Project Structure

```
new-auth-system/
│── src/
│   ├── controllers/
│   │   └── auth.controller.js   # OTP & Auth logic
│   ├── middlewares/
│   │   ├── mailer.js            # Email transport setup
│   │   └── sendCode.js          # Function to send OTP
│   │   └── auth.middleware.js         # Function to send OTP
│   ├── prisma/
│   │   └── prismaClient.js      # Prisma client instance
│   ├── routes/
│   │   └── auth.routes.js       # Auth API routes
│   ├── utils/
│   │   ├── apiError.js          # Custom error handler
│   │   ├── apiResponse.js       # Standardized response format
│   │   └── asyncHandler.js      # Async error wrapper
│   └── index.js                 # App entry point
│   └── app.js                 # App entry point
│
├── prisma/
│   └── schema.prisma            # Database schema
│
├── .env                         # Environment variables
├── package.json
└── README.md
```

---

## ⚙️ Installation

1. **Clone the repo**

```bash
git clone https://github.com/your-username/new-auth-system.git
cd new-auth-system
```

2. **Install dependencies**

```bash
npm install
```

3. **Setup environment variables** (`.env`)

```env
PORT=3000

# JWT
ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Arcjet
ARCJET_KEY=your_arcjet_key

# Email (Nodemailer)
SMTP_HOST=smtp.your-email.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASS=your_password

# Node environment
NODE_ENV=development
```

4. **Setup Prisma**

```bash
npx prisma init
npx prisma migrate dev --name init
```

Make sure your `schema.prisma` includes at least:

```prisma
model User {
  id           String    @id @default(cuid())
  email        String    @unique
  name         String?
  isVerified   Boolean   @default(false)
  refreshToken String?   @db.Text
  createdAt    DateTime  @default(now())
  updatedAt    DateTime  @updatedAt
  
  otps         Otp[]
  
  @@index([email])
}

model Otp {
  id         String   @id @default(cuid())
  userId     String
  code       String   // Hashed OTP
  expiresAt  DateTime
  attempts   Int      @default(0)
  createdAt  DateTime @default(now())
  
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId])
  @@index([expiresAt])
}
```

5. **Run the dev server**

```bash
npm run dev
```

---

## 🔒 Security Considerations

* OTP stored **hashed** in DB (bcrypt).
* OTP expires in **10 minutes**.
* Max **3 attempts** per OTP.
* Refresh token stored in DB for invalidation.
* Secure cookies with `httpOnly`, `sameSite=strict`, `secure` in production.

---

## 📜 License

MIT License © 2025

---