import express, { Request, Response } from "express";
import { body, validationResult } from "express-validator";
import argon2, { argon2id } from 'argon2';
import { sendOTPEmail } from "../../config/mail";
import dragonflyClient from "../../config/dragonfly";
import { argon2Config } from "../../config/argon2_config";
import prisma from "../../config/prisma";
const router = express.Router();

router.post(
  "/",
  [
    body("username")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),
    body("name").isLength({ min: 3 })
      .withMessage("Name must be at least 3 characters long"),
    body("email").isEmail().withMessage("Please enter a valid email address"),
    body("password")
      .isLength({ min: 7 })
      .withMessage("Password must be at least 7 characters long")
      .matches(/[A-Z]/)
      .withMessage("Password must contain at least one uppercase letter")
      .matches(/[a-z]/)
      .withMessage("Password must contain at least one lowercase letter")
      .matches(/\d/)
      .withMessage("Password must contain at least one digit")
      .matches(/[@$!%*?&]/)
      .withMessage("Password must contain at least one special character"),
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email, username, password, name } = req.body;
  
    
    try {
      const usernameCheck = await prisma.user.findUnique({
        where: { username: username }
      });
      if (usernameCheck) {
        return res.status(400).json({ message: 'This username is already registered' });
      }

      const emailCheck = await prisma.user.findUnique({
        where: { email: email }
      });
      if (emailCheck) {
        return res.status(400).json({ message: 'This email is already registered' });
      }

      const createdOtp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOtp = await argon2.hash(createdOtp, argon2Config);

      const hashedPassword = await argon2.hash(password, argon2Config);

      await dragonflyClient.setEx(`signup_otp:${email}`, 180, hashedOtp);
      await prisma.user.create({
        data: {
          username,
          email,
          name,
          password: hashedPassword,
          isVerified: false,
          type: 'local'
        }
      });

      sendOTPEmail(email, createdOtp).catch((error) => {
        console.error("OTP email sending failed:", error);
      });

      res.status(201).json({ message: 'User successfully registered' });
    } catch (error) {
      console.error(error);

      res.status(500).json({ message: 'Server error. Please try again later.' });
    }
  }
);

export default router;
