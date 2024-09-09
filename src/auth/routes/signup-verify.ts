import { Request, Response, Router } from "express";
import { body, validationResult } from "express-validator";
import dragonflyClient from "../../config/dragonfly";
import { pool } from "../../config/db";
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';

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
        const storedOTP = await dragonflyClient.get(email);

        if (storedOTP && await argon2.verify(storedOTP, otp)) {
            await dragonflyClient.del(email);
            await pool.query('UPDATE users SET isverified = TRUE WHERE email = $1', [email]);
            
            const userResult = await pool.query('SELECT id, username, email FROM users WHERE email = $1', [email]);
            const user = userResult.rows[0];

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