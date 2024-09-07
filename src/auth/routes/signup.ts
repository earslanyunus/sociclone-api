import express, { Request, Response } from "express";
import { body, validationResult } from "express-validator";
import { pool } from "../../config/db";
import argon2, { argon2id } from 'argon2';
import { sendOTPEmail } from "../../config/mail";
import dragonflyClient from "../../config/dragonfly";

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
    console.time("Total Request Time");
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, username, password,name } = req.body;
    try {
      const usernameCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (usernameCheck.rows.length > 0) {
        return res.status(400).json({ message: 'This username is already registered' });
      }

      const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (emailCheck.rows.length > 0) {
        return res.status(400).json({ message: 'This email is already registered' });
      }

      const createdOtp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOtp = await argon2.hash(createdOtp, {
        type: argon2id,
        memoryCost: 12288,
        parallelism: 1,
        timeCost: 3
      });

      const hashedPassword = await argon2.hash(password, {
        type: argon2id,
        memoryCost: 12288,
        parallelism: 1,
        timeCost: 3
      });

      await dragonflyClient.setEx(email, 180, hashedOtp);
      await pool.query('INSERT INTO users (username, email, password, isverified,name) VALUES ($1, $2, $3, false, $4)', [username, email, hashedPassword,name]);

      sendOTPEmail(email, createdOtp).catch((error) => {
        console.error("Failed to send OTP email:", error);
      });

      res.status(201).json({ message: 'User successfully registered' });
    } catch (error) {
      res.status(500).json({ message: 'Server error. Please try again later.' });
    }
  }
);

export default router;
