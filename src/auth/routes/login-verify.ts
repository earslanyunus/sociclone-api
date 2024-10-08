import express from "express";
import { body, validationResult } from "express-validator";
import dragonflyClient from "../../config/dragonfly";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
import prisma from "../../config/prisma";

const router = express.Router();
const isProduction = process.env.NODE_ENV === 'production';

router.post("/", [
  body("email").isEmail().withMessage("Enter a valid email address"),
  body("otp").isLength({ min: 6, max: 6 }).withMessage("Enter a valid OTP"),
], async (req: express.Request, res: express.Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, otp } = req.body;

  try {
    const storedHashedOtp = await dragonflyClient.get(`login_otp:${email}`);
    if (!storedHashedOtp) {
      return res.status(400).json({ message: "OTP expired or invalid" });
    }

    const isValidOtp = await argon2.verify(storedHashedOtp, otp);
    if (!isValidOtp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    await dragonflyClient.del(`login_otp:${email}`);

    const user = await prisma.user.findUnique({
        where: {
            email: email
        }
    });
    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }
    const access_token = jwt.sign({ id: user.id }, process.env.JWT_SECRET as string, { expiresIn: "15m",issuer:process.env.JWT_ISSUER,audience:process.env.JWT_AUDIENCE,subject:user.id.toString(),  });
    const refresh_token = jwt.sign({ id: user.id }, process.env.JWT_SECRET as string, { expiresIn: "7d",issuer:process.env.JWT_ISSUER,audience:process.env.JWT_AUDIENCE,subject:user.id.toString(), });

    res.cookie("access_token", access_token, { httpOnly: true, secure: process.env.NODE_ENV !== "development", sameSite: "strict", maxAge: 15 * 60 * 1000 });
    res.cookie("refresh_token", refresh_token, { httpOnly: true, secure: process.env.NODE_ENV !== "development", sameSite: "strict", maxAge: 7 * 24 * 60 * 60 * 1000 });

    return res.status(200).json({ message: "Login successful", user:{username:user.username,email:user.email,name:user.name} });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
