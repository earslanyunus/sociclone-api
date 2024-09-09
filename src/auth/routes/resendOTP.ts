import { Request, Response, Router } from "express";
import dragonflyClient from "../../config/dragonfly";
import { body, validationResult } from "express-validator";
import argon2, { argon2id } from 'argon2'
import { sendOTPEmail } from "../../config/mail";
import { pool } from "../../config/db";
import { argon2Config } from "../../config/argon2_config";
const router = Router()


router.post('/',[body('email').isEmail().withMessage('Invalid email')],async(req:Request,res:Response)=>{
    const {email} = req.body
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const user = userCheck.rows[0];
        if (user.isverified) {
            return res.status(400).json({ message: 'User is already verified. No need to resend OTP.' });
        }

        const existingOtp = await dragonflyClient.get(email);
        if (existingOtp) {
            return res.status(400).json({ message: 'OTP already sent. Please wait for 3 minutes or use the current OTP.' })
        }

        const createdOtp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await argon2.hash(createdOtp, argon2Config);

        await dragonflyClient.setEx(email, 180, hashedOtp);
        await sendOTPEmail(email, createdOtp);
        res.status(200).json({ message: 'OTP sent to your email.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    
    }
})

export default router