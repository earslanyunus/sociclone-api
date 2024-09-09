import { Router, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import argon2 from 'argon2'
import { argon2Config } from "../../config/argon2_config";
import { pool } from "../../config/db";
import { sendOTPEmail } from "../../config/mail";
import dragonflyClient from "../../config/dragonfly";
import jwt from "jsonwebtoken";
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
        const user = userCheck.rows[0]

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await argon2.hash(otp,argon2Config);

        await dragonflyClient.setEx(`forgotpassword_otp:${user.email}`,300, hashedOtp); 

        await sendOTPEmail(user.email, otp);

        const part1Hash = jwt.sign({email:user.email},process.env.JWT_SECRET as string,{expiresIn:'5m',issuer:process.env.JWT_ISSUER,audience:process.env.JWT_AUDIENCE})

        res.status(200).json({message: 'OTP sent', part1Hash});

    } catch (error) {
        console.error(error);
        res.status(500).json({message: 'Server error. Please try again later.'});
    }
})

export default router
