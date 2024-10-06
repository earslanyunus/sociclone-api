import { body, validationResult } from "express-validator";
import argon2 from 'argon2'
import dragonflyClient from "../../config/dragonfly";
import jwt from "jsonwebtoken";
import { Router, Request, Response } from "express";
import prisma from "../../config/prisma";

const router = Router()

router.post('/', [body('part1Hash').isString().withMessage('Invalid part1Hash'), body('otp').isString().withMessage('Invalid otp')],
async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { part1Hash, otp } = req.body;
    
    try {
        let decoded;
        try {
            decoded = jwt.verify(part1Hash, process.env.JWT_SECRET as string) as { email: string, iss?: string, aud?: string };
        } catch (jwtError) {
            console.error('Invalid part1Hash', jwtError);
            return res.status(401).json({ message: 'Invalid part1Hash' });
        }
        const hashedOtp = await dragonflyClient.get(`forgotpassword_otp:${decoded.email}`); 
        if(hashedOtp){
            const result = await argon2.verify(hashedOtp,otp)
            if(result){
                const part2Hash = jwt.sign({email:decoded.email},process.env.JWT_SECRET as string,{expiresIn:'15m',issuer:process.env.JWT_ISSUER,audience:process.env.JWT_AUDIENCE})
                await dragonflyClient.del(`forgotpassword_otp:${decoded.email}`)
                res.status(200).json({message: 'OTP verified', part2Hash});
            }
            else{
                res.status(401).json({ message: 'Invalid OTP.' });
            }
        }
        else{
            res.status(401).json({ message: 'Invalid OTP.' });
        }
    } catch (error) {
        console.error('Sunucu hatası:', error);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
})

export default router
