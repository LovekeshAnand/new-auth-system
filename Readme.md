# OTP-Based Authentication System 🔐

A **secure, production-ready authentication system** that eliminates passwords entirely. Built with **Node.js**, **Express**, **Prisma**, and **JWT**, this system uses time-limited OTPs sent via email for a passwordless authentication experience.

![Node.js](https://img.shields.io/badge/node.js-18+-green.svg)
![Express](https://img.shields.io/badge/express-5.1-lightgrey.svg)
![Prisma](https://img.shields.io/badge/prisma-6.14-blue.svg)
![JWT](https://img.shields.io/badge/JWT-9.0-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## ✨ Features

- **🔑 Passwordless Authentication**: No passwords to remember—login with OTP codes sent to your email
- **📧 Email Validation**: Arcjet integration blocks disposable and invalid email addresses
- **⏱️ Time-Limited OTPs**: Codes expire after 10 minutes with maximum 3 verification attempts
- **🛡️ Rate Limiting**: Prevents abuse with intelligent rate limiting on OTP requests
- **🔄 Token Refresh**: Seamless session management with access and refresh tokens
- **🍪 Secure Cookies**: HttpOnly, SameSite, and Secure flags for production safety
- **💾 Database Persistence**: Refresh tokens stored and validated server-side
- **🚀 Production Ready**: Built with security best practices and error handling

## 🎯 How It Works

```
User enters email → Arcjet validates → OTP generated & hashed → Email sent
    ↓
User enters OTP → Verify (max 3 attempts) → Generate JWT tokens → Set secure cookies
    ↓
Protected routes → Verify access token → Auto-refresh if expired
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and npm
- **PostgreSQL** / MySQL / SQLite database
- **SMTP server** credentials (Gmail, SendGrid, etc.)
- **Arcjet account** (for email validation)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/LovekeshAnand/new-auth-system.git
cd new-auth-system
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure environment variables**

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
ACCESS_TOKEN_SECRET=your_super_secret_access_key_min_32_chars
REFRESH_TOKEN_SECRET=your_super_secret_refresh_key_min_32_chars
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Arcjet Configuration
ARCJET_KEY=ajkey_your_arcjet_api_key_here

# Email Configuration (Nodemailer)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-specific-password

# Database
DATABASE_URL="postgresql://user:password@localhost:5432/authdb?schema=public"
```

4. **Setup the database**
```bash
npx prisma generate
npx prisma migrate dev --name init
```

5. **Start the development server**
```bash
npm run dev
```

The server will start on `http://localhost:3000`

## 📦 Project Structure

```
new-auth-system/
├── src/
│   ├── controllers/
│   │   └── auth.controller.js      # Authentication logic (OTP, login, refresh)
│   ├── middlewares/
│   │   ├── auth.middleware.js      # JWT verification middleware
│   │   ├── mailer.js               # Nodemailer configuration
│   │   └── sendCode.js             # OTP email sender
│   ├── prisma/
│   │   └── prismaClient.js         # Prisma client singleton
│   ├── routes/
│   │   └── auth.routes.js          # API route definitions
│   ├── utils/
│   │   ├── apiError.js             # Custom error class
│   │   ├── apiResponse.js          # Standardized response format
│   │   └── asyncHandler.js         # Async/await error wrapper
│   ├── app.js                      # Express app configuration
│   └── index.js                    # Server entry point
│
├── prisma/
│   └── schema.prisma               # Database schema definition
│
├── public/
│   └── temp/                       # Temporary file storage
│
├── .env                            # Environment variables (gitignored)
├── .gitignore
├── package.json
└── README.md
```

## 🔌 API Endpoints

### Authentication Routes

#### `POST /api/v1/auth/request-otp`
Request an OTP code to be sent to your email

**Request Body:**
```json
{
  "email": "user@example.com",
  "name": "John Doe"  // Optional, for new users
}
```

**Response:**
```json
{
  "statusCode": 200,
  "success": true,
  "message": "OTP sent successfully",
  "data": {
    "email": "user@example.com",
    "expiresIn": "10 minutes"
  }
}
```

---

#### `POST /api/v1/auth/verify-otp`
Verify OTP and receive authentication tokens

**Request Body:**
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**Response:**
```json
{
  "statusCode": 200,
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "cuid_123",
      "email": "user@example.com",
      "name": "John Doe",
      "isVerified": true
    },
    "accessToken": "eyJhbGciOiJIUzI1N...",
    "refreshToken": "eyJhbGciOiJIUzI1N..."
  }
}
```

**Cookies Set:**
- `accessToken` (15 min expiry)
- `refreshToken` (7 day expiry)

---

#### `POST /api/v1/auth/resend-otp`
Resend OTP if the previous one expired

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

---

#### `POST /api/v1/auth/refresh-token`
Refresh expired access token using refresh token

**Headers:**
```
Cookie: refreshToken=eyJhbGciOiJIUzI1N...
```

**Response:**
```json
{
  "statusCode": 200,
  "success": true,
  "message": "Access token refreshed",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1N..."
  }
}
```

---

#### `POST /api/v1/auth/logout`
Logout and invalidate refresh token

**Headers:**
```
Authorization: Bearer <accessToken>
Cookie: refreshToken=<refreshToken>
```

**Response:**
```json
{
  "statusCode": 200,
  "success": true,
  "message": "Logged out successfully",
  "data": null
}
```

---

#### `GET /api/v1/auth/me`
Get current user information (protected route)

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "statusCode": 200,
  "success": true,
  "message": "User retrieved successfully",
  "data": {
    "id": "cuid_123",
    "email": "user@example.com",
    "name": "John Doe",
    "isVerified": true,
    "createdAt": "2025-01-15T10:30:00.000Z"
  }
}
```

## 🛠️ Tech Stack

### Core Technologies
- **Node.js** (v18+): JavaScript runtime
- **Express** (v5.1): Web framework
- **Prisma** (v6.14): Modern ORM for database operations
- **JWT** (v9.0): Stateless authentication tokens

### Security & Validation
- **Arcjet** (v1.0-beta): Email validation and bot protection
- **Bcrypt** (v6.0): Secure OTP hashing
- **Cookie Parser**: Secure cookie handling

### Email & Communication
- **Nodemailer** (v7.0): Email delivery system

### Development Tools
- **Nodemon**: Hot reload during development
- **dotenv**: Environment variable management

## 🗄️ Database Schema

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
  code       String   // Hashed with bcrypt
  expiresAt  DateTime
  attempts   Int      @default(0)
  createdAt  DateTime @default(now())
  
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId])
  @@index([expiresAt])
}
```

## 🔒 Security Features

### OTP Security
- ✅ **Hashed Storage**: OTPs stored as bcrypt hashes (never plaintext)
- ✅ **Time Expiration**: 10-minute validity window
- ✅ **Attempt Limiting**: Maximum 3 verification attempts per code
- ✅ **Auto-Cleanup**: Expired OTPs automatically invalidated

### Token Security
- ✅ **Short-lived Access Tokens**: 15-minute expiry reduces exposure window
- ✅ **Secure Refresh Tokens**: 7-day expiry with server-side validation
- ✅ **Token Rotation**: New tokens generated on refresh
- ✅ **Revocation Support**: Refresh tokens can be invalidated in database

### Cookie Security
- ✅ **HttpOnly**: Prevents JavaScript access to cookies
- ✅ **SameSite=Strict**: CSRF protection
- ✅ **Secure Flag**: HTTPS-only in production
- ✅ **Domain Scoping**: Cookies bound to specific domain

### Email Security
- ✅ **Arcjet Validation**: Blocks disposable and invalid emails
- ✅ **Rate Limiting**: Prevents email bombing attacks
- ✅ **Cooldown Period**: Prevents rapid OTP resend requests

## 🎨 Error Handling

All errors follow a consistent format:

```json
{
  "statusCode": 400,
  "success": false,
  "message": "Invalid OTP code",
  "errors": [],
  "data": null
}
```

### Common Error Codes
- **400**: Bad Request (invalid input, expired OTP)
- **401**: Unauthorized (invalid token, missing auth)
- **403**: Forbidden (rate limit exceeded)
- **404**: Not Found (user not found)
- **500**: Internal Server Error

## 🧪 Testing

### Test OTP Flow
```bash
# 1. Request OTP
curl -X POST http://localhost:3000/api/v1/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "name": "Test User"}'

# 2. Verify OTP (check your email for the code)
curl -X POST http://localhost:3000/api/v1/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "code": "123456"}'

# 3. Access Protected Route
curl http://localhost:3000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🚀 Deployment

### Environment Variables for Production
```env
NODE_ENV=production
PORT=3000

# Use strong, random secrets (minimum 32 characters)
ACCESS_TOKEN_SECRET=<generate-with-openssl-rand-base64-32>
REFRESH_TOKEN_SECRET=<generate-with-openssl-rand-base64-32>

# Production database
DATABASE_URL="postgresql://user:pass@host:5432/proddb"

# Production SMTP (use service like SendGrid, AWS SES)
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=<your-sendgrid-api-key>

# Arcjet production key
ARCJET_KEY=<your-production-arcjet-key>
```

## 📝 License

MIT License © 2025 Lovekesh Anand

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.

## 📧 Contact

**Lovekesh Anand**
- GitHub: [@LovekeshAnand](https://github.com/LovekeshAnand)
- Repository: [new-auth-system](https://github.com/LovekeshAnand/new-auth-system)

For questions or support, please open an issue on GitHub.

---

**Built with 🔐 security and ❤️ for developers**