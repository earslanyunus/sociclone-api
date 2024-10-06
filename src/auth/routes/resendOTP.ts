import { Request, Response, Router } from "express";
import dragonflyClient from "../../config/dragonfly";
import { body, validationResult } from "express-validator";
import argon2, { argon2id } from 'argon2'
import { sendOTPEmail } from "../../config/mail";
import { argon2Config } from "../../config/argon2_config";
const router = Router()


router.post('/',[body('email').isEmail().withMessage('Invalid email'),body('type').isString().withMessage('Invalid type')],async(req:Request,res:Response)=>{
    const {email,type} = req.body
    try {
        
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        if(type === 'signup'){
            const existingOtp = await dragonflyClient.get(`signup_otp:${email}`);
            if (existingOtp) {
                return res.status(400).json({ message: 'OTP already sent. Please wait for 3 minutes or use the current OTP.' })
            }
            const createdOtp = Math.floor(100000 + Math.random() * 900000).toString();
            const hashedOtp = await argon2.hash(createdOtp, argon2Config);
            await dragonflyClient.setEx(`signup_otp:${email}`, 180, hashedOtp);
            await sendOTPEmail(email, createdOtp);
            res.status(200).json({ message: 'OTP sent to your email.' });
        }
        else if(type === 'login'){
            const existingOtp = await dragonflyClient.get(`login_otp:${email}`);
            if (existingOtp) {
                return res.status(400).json({ message: 'OTP already sent. Please wait for 3 minutes or use the current OTP.' })
            }
            const createdOtp = Math.floor(100000 + Math.random() * 900000).toString();
            const hashedOtp = await argon2.hash(createdOtp, argon2Config);
            await dragonflyClient.setEx(`login_otp:${email}`, 180, hashedOtp);
            await sendOTPEmail(email, createdOtp);
            res.status(200).json({ message: 'OTP sent to your email.' });
        }
        else if(type === 'forgotpassword'){
            const existingOtp = await dragonflyClient.get(`forgotpassword_otp:${email}`);
            if (existingOtp) {
                return res.status(400).json({ message: 'OTP already sent. Please wait for 3 minutes or use the current OTP.' })
            }
            const createdOtp = Math.floor(100000 + Math.random() * 900000).toString();
            const hashedOtp = await argon2.hash(createdOtp, argon2Config);
            await dragonflyClient.setEx(`forgotpassword_otp:${email}`, 180, hashedOtp);
            await sendOTPEmail(email, createdOtp);
            res.status(200).json({ message: 'OTP sent to your email.' });
        }
        else{
            return res.status(400).json({ message: 'Invalid type.' })
        }
        
       

       
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    
    }
})

export default router