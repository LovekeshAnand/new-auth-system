import nodemailer from 'nodemailer'
import dotenv from 'dotenv'
import { asyncHandler } from '../utils/asyncHandler.js';

dotenv.config()

const transporter = nodemailer.createTransport({
    host: "in-v3.mailjet.com",
    port: 587,
    auth: {
        user: process.env.MAILJET_API_KEY,
        pass: process.env.MAILJET_API_SECRET,
    },
});

const sendMail = asyncHandler(async ({ to, subject, text, html }) => {
  try {
    const info = await transporter.sendMail({
      from: process.env.MAILJET_SENDER_EMAIL,
      to,
      subject,
      text,
      html,
    });
    return info;
  } catch (error) {
    throw error;
  }
});

export {sendMail}