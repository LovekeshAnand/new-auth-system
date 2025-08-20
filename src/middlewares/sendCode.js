import { sendMail } from "./mailer.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";


const sendOtpEmail = asyncHandler(async(req, res, next) => {
    const email = req.userEmail;
    const otp = req.otp;

    if (!email || !otp) {
        throw new ApiError(400, "Email or OTP is missing!")
    }

    const subject = "Your OTP to login in auth-system!"
    const text = `Your OTP code is: ${otp}`;
    const html = `<p>Your OTP code is: <b>${otp}</b></p>`;

    try {
        await sendMail({to: email, subject, text, html});
        console.log(`OTP send to ${email}`);
        next();
        
    } catch (error) {
        throw new ApiError(500, "Failed to send OTP email!")
    }
})

export {sendOtpEmail}