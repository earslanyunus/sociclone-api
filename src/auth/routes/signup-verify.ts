import { Request, Response, Router } from "express";
import { body, validationResult } from "express-validator";
import dragonflyClient from "../../config/dragonfly";
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import prisma from "../../config/prisma";

const router = Router();

router.post(
  "/",
  [
    body("email").isEmail().withMessage("Enter a valid email address"),
    body("otp").isLength({min:6,max:6}).withMessage("Enter a valid OTP")
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }
    const {email, otp} = req.body;
    try {
        const storedOTP = await dragonflyClient.get(`signup_otp:${email}`);

        if (storedOTP && await argon2.verify(storedOTP, otp)) {
            await dragonflyClient.del(`signup_otp:${email}`);
            await prisma.user.update({
                where: { email: email },
                data: { isVerified: true }
            });
          
            
            const user = await prisma.user.findUnique({
                where: { email: email },
                select: { id: true, username: true, email: true, name: true }
            });

            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }

            const access_token = jwt.sign({ id: user.id }, process.env.JWT_SECRET as string, { expiresIn: "15m",issuer:process.env.JWT_ISSUER,audience:process.env.JWT_AUDIENCE,subject:user.id.toString(),  });
            const refresh_token = jwt.sign({ id: user.id }, process.env.JWT_SECRET as string, { expiresIn: "7d",issuer:process.env.JWT_ISSUER,audience:process.env.JWT_AUDIENCE,subject:user.id.toString(), });

            res.cookie("access_token", access_token, { httpOnly: true, secure: true });
            res.cookie("refresh_token", refresh_token, { httpOnly: true, secure: true });

            return res.status(200).json({ message: "Email address has been successfully verified and logged in", user:{username:user.username,email:user.email,name:user.name} });

           
        } else {
            return res.status(400).json({message: "Invalid OTP"});
        }
        
    } catch (error) {
        console.error(error);
        res.status(500).json({message: 'Server error. Please try again later.'});
    }
  }
);

export default router;