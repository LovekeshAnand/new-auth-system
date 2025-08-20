import { Router } from "express";
import {
    requestOtp,
    verifyOtp,
    resendOtp,
    refreshAccessToken,
    logout
} from '../controllers/auth.controller.js';

const router = Router()

router.post('/request-otp', requestOtp);
router.post('/verify-otp', verifyOtp);
router.post('/resend-otp', resendOtp);
router.post('/refresh-token', refreshAccessToken);
router.post('/logout', logout);

export default router;