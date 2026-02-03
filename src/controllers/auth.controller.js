import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import arcjet, { validateEmail } from '@arcjet/node';
import { sendMail } from "../middlewares/mailer.js";
import { sendOtpEmail } from "../middlewares/sendCode.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import prisma from "../prisma/prismaClient.js";


//initializing arcjet
const aj = arcjet({
    key: process.env.ARCJET_KEY,
    rules: [
        validateEmail({
            mode: "LIVE",
            block: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS"]
        }),
    ],
})

//generate random 6 digit otp
const generateOtp = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

//Generate JWT tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { userId },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRY || '1d'}
    );

    const refreshToken = jwt.sign(
        { userId },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRY || '10d'}
    );

    return { accessToken, refreshToken};
}

const requestOtp = asyncHandler(async(req, res) => {
    const { email } = req.body;

    if (!email) {
        throw new ApiError(400, "Email is missing!")
    }

    //validate email with arcjet
    const decision = await aj.protect(req, { email });

    if (decision.conclusion === "DENY") {
        const emailTypes = decision?.reason?.emailTypes || [];
        let errorMessage = "Invalid email address!";

            if (emailTypes.includes("DISPOSABLE")) {
                errorMessage = "Disposable emails are not allowed!";
            } else if (emailTypes.includes("INVALID")) {
                errorMessage = "Please provide a valid email address!";
            } else if (emailTypes.includes("NO_MX_RECORDS")) {
                errorMessage = "Email does not exist!";
            }

        throw new ApiError(400, errorMessage);
    }

    let user = await prisma.user.findUnique({where: {email}});

    if (!user) {
        //Create a new user
        user = await prisma.user.create({
            data: {
                email,
                name: email.split("@")[0],
                isVerified: false
            }
        });
    }

    const existingOtp = await prisma.otp.findFirst({
        where: {
            userId: user.id,
            expiresAt: { gt: new Date()}
        }
    });

    if (existingOtp) {
        const timeSinceCreated = Date.now() - Date(existingOtp.createdAt).getTime();
        if (timeSinceCreated < 60000) {
            const waitTime = Math.ceil((60000 - timeSinceCreated) /1000);
            throw new ApiError(429, `Please wait ${waitTime} seconds before requesting a new OTP!`)
        }
    }

    //Generate otp
    const otp = generateOtp()
    const hashedOtp = await bcrypt.hash(otp, 10)

    //set otp expiry(10 minutes)
    const otpExpiry = new Date(Date.now() + 10 * 60 *1000);
    
    //delete any exisitng otp for this user.
    await prisma.otp.deleteMany({
        where: { userId: user.id}
    })

    //create new otp entry
    await prisma.otp.create({
        data: {
            userId: user.id,
            code: hashedOtp,
            expiresAt: otpExpiry,
            attempts: 0
        }
    });


    //Send otp via email using your middleware
    req.userEmail = email;
    req.otp = otp;
    await sendOtpEmail(req, res, () => {})

    return res.status(200).json(new ApiResponse(200, {
        email,
        message: "Otp sent successfully to yor email"
    }, "Otp sent successfully!"));
})

//verify otp
const verifyOtp = asyncHandler(async(req, res) => {
    const {email, otp} = req.body;

    if (! email || !otp) {
        throw new ApiError(400, "Email and otp are required!")
    }

    //validate otp formats
    if (!/^\d{6}$/.test(otp)) {
        throw new ApiError(400, "Invalid OTP format!")
    }

    //find user
    const user = await prisma.user.findUnique({
        where: {email}
    })

    if (!user) {
        throw new ApiError(404, "User not found!")
    }

    //find otp entry
    const otpEntry = await prisma.otp.findFirst({
        where: { userId: user.id },
        orderBy: { createdAt: 'desc' }
    })

    if (!otpEntry) {
        throw new ApiError(400, "No otp found, please request a new one!")
    }

    //check if the otp has expired
    if (new Date() > otpEntry.expiresAt) {
        await prisma.otp.delete({
            where: {
                id: otpEntry.id
            }
        });
        throw new ApiError(400, "Otp has expired. Please request a new one!")
    }

    // Check if maximum attempts exceeded
    if (otpEntry.attempts >= 3) {
        await prisma.otp.delete({
            where: {
                id: otpEntry.id
            }
        });
        throw new ApiError(400, "Maximum otp attempts exceeded. Please request a new one.")
    }

    //verify otp
    const isValidOtp = await bcrypt.compare(otp, otpEntry.code)

    if (!isValidOtp) {
        //increment attempts
        await prisma.otp.update({
            where: { id: otpEntry.id },
            data: { attempts: { increment: 1 } }
        });

        const remainingAttempts = 3 - (otpEntry.attempts + 1);
        throw new ApiError(400, `Invalid OTP. ${remainingAttempts} attempts remaining`);
    }

    //otp is valid - delete it
    await prisma.otp.delete({
        where: {
            id: otpEntry.id
        }
    })

    //mark user as verified
    const updatedUser = await prisma.user.update({
        where: {id: user.id},
        data: { isVerified: true },
        select: {
            id: true,
            email: true,
            name: true,
            isVerified: true
        }
    });

    //generate tokens
    const {accessToken, refreshToken} = generateTokens(user.id)

    //save refresh token to database
    await prisma.user.update({
        where: { id: user.id },
        data: { refreshToken }
    });

    //set cookies
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    };

    res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000 //15 minutes
    })

    res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 *  60 * 1000 //7days
    })

    return res.status(200).json(
        new ApiResponse(200, {
            user : updatedUser,
            accessToken,
            message: "Authentication successful"
        }, "User authenticated successfully")
    )
})

// Resend OTP
const resendOtp = asyncHandler(async(req, res) => {
    const { email } = req.body;
    
    if (!email) {
        throw new ApiError(400, "Email is required");
    }
    
    // Validate email with Arcjet again
    const decision = await aj.protect(req, { email });
    
    if (decision.isDenied()) {
        throw new ApiError(400, "Invalid email address");
    }
    
    // Find user
    const user = await prisma.user.findUnique({
        where: { email }
    });
    
    if (!user) {
        throw new ApiError(404, "User not found. Please request OTP first");
    }
    
    // Check for existing OTP
    const existingOtp = await prisma.otp.findFirst({
        where: { 
            userId: user.id,
            expiresAt: { gt: new Date() }
        }
    });
    
    if (existingOtp) {
        const timeSinceCreated = Date.now() - new Date(existingOtp.createdAt).getTime();
        if (timeSinceCreated < 60000) {
            const waitTime = Math.ceil((60000 - timeSinceCreated) / 1000);
            throw new ApiError(429, `Please wait ${waitTime} seconds before requesting a new OTP`);
        }
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
    
    // Delete old OTPs and create new one
    await prisma.otp.deleteMany({
        where: { userId: user.id }
    });
    
    await prisma.otp.create({
        data: {
            userId: user.id,
            code: hashedOtp,
            expiresAt: otpExpiry,
            attempts: 0
        }
    });
    
    // Send OTP
    req.userEmail = email;
    req.otp = otp;
    await sendOtpEmail(req, res, () => {});
    
    return res.status(200).json(
        new ApiResponse(200, { 
            email,
            message: "New OTP sent successfully"
        }, "OTP resent successfully")
    );
});

// Refresh access token
const refreshAccessToken = asyncHandler(async(req, res) => {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    
    if (!incomingRefreshToken) {
        throw new ApiError(401, "Refresh token not found");
    }
    
    try {
        const decoded = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );
        
        const user = await prisma.user.findUnique({
            where: { id: decoded.userId }
        });
        
        if (!user || user.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Invalid refresh token");
        }
        
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user.id);
        
        // Update refresh token in database
        await prisma.user.update({
            where: { id: user.id },
            data: { refreshToken: newRefreshToken }
        });
        
        // Set new cookies
        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        };
        
        res.cookie('accessToken', accessToken, {
            ...cookieOptions,
            maxAge: 15 * 60 * 1000
        });
        
        res.cookie('refreshToken', newRefreshToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        return res.status(200).json(
            new ApiResponse(200, { 
                accessToken,
                message: "Tokens refreshed successfully"
            }, "Access token refreshed")
        );
    } catch (error) {
        throw new ApiError(401, "Invalid or expired refresh token");
    }
});

// Logout
const logout = asyncHandler(async(req, res) => {
    const refreshToken = req.cookies?.refreshToken;
    
    if (refreshToken) {
        try {
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            
            // Clear refresh token from database
            await prisma.user.update({
                where: { id: decoded.userId },
                data: { refreshToken: null }
            });
        } catch (error) {
            // Token might be invalid, but still want to clear cookies
        }
    }
    
    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    
    return res.status(200).json(
        new ApiResponse(200, {
            message: "Logged out successfully"
        }, "Logged out successfully")
    );
});

export {
    requestOtp,
    verifyOtp,
    resendOtp,
    refreshAccessToken,
    logout
};