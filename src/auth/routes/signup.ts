import express, { Request, Response } from "express";
import { body, validationResult } from "express-validator";
import { pool } from "../../config/db";
import bcrypt from 'bcrypt'
import { sendOTPEmail } from "../../config/mail";

const router = express.Router();

router.post(
  "/",
  [
    body("username")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),
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

    const {email,username,password} = req.body
    try {
        const usernameCheck = await pool.query('SELECT * FROM users WHERE username = $1',[username])
        if (usernameCheck.rows.length>0) {
            return res.status(400).json({message:'This username is already registered'})
            
        }
        const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1',[email])
        if (emailCheck.rows.length>0) {
            return res.status(400).json({message:'This email is already registered'})
        }
        const hashedPassword = await bcrypt.hash(password,12)

        await pool.query('INSERT INTO users (username, email, password,isverified) VALUES ($1, $2, $3,false)',[username,email,hashedPassword])
        
        await sendOTPEmail(email,'000000')
        res.status(201).json({message:'User successfully registered'})
        
    } catch (error) {
        console.error(error)
        res.status(500).json({message:'Server error. Please try again later.'})
        
    }
    
  }
);

export default router;
