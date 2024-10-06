import { Router, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import argon2 from 'argon2'
import { argon2Config } from "../../config/argon2_config";
import jwt from "jsonwebtoken";
import prisma from "../../config/prisma";
const router = Router()

router.post('/',[body('part2Hash').isString().withMessage('Invalid part2Hash'),
    body('newPassword')
    .isLength({ min: 7 })
    .withMessage("Password must be at least 7 characters long")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/\d/)
    .withMessage("Password must contain at least one digit")],async(req:Request,res:Response)=>{
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const {part2Hash,newPassword} = req.body
    try {
        let decoded;
        try {
            decoded = jwt.verify(part2Hash, process.env.JWT_SECRET as string) as { email: string, iss?: string, aud?: string };
        } catch (jwtError) {
            console.error('Invalid part2Hash', jwtError);
            return res.status(401).json({ message: 'Invalid part2Hash' });
        }
        if (decoded.iss !== process.env.JWT_ISSUER || decoded.aud !== process.env.JWT_AUDIENCE) {
            return res.status(401).json({ message: 'Invalid token.' });
        }

        const {email} = decoded
        const userCheck = await prisma.user.findUnique({
            where: {
                email: email
            }
        });
        if (!userCheck) {
            return res.status(404).json({ message: 'User not found.' });
        }
        const hashedPassword = await argon2.hash(newPassword,argon2Config)

        await prisma.user.update({
            where: {
                email: email
            },
            data: {
                password: hashedPassword
            }
        });

        res.status(200).json({message: 'Password updated'});
        
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error. Please try again later.' });

        
    }
})

export default router
