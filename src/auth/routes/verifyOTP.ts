import { Request, Response, Router } from "express";
import { body, validationResult } from "express-validator";
import dragonflyClient from "../../config/dragonfly";
import { pool } from "../../config/db";
import argon2 from 'argon2'
const router = Router();

router.post(
  "/",
  [
    body("email")
    .isEmail()
    .withMessage("Please enter a valid email address"),
    body("otp")
    .isAlphanumeric('en-US').withMessage('Please enter a valid otp')
    .isLength({min:6,max:6}).withMessage("Please enter a valid otp")


],
  async (req: Request, res: Response) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()})
    }
    const {email,otp} = req.body
    try {
        const storedOTP = await dragonflyClient.get(email)

        if (storedOTP && await argon2.verify(storedOTP,otp)) {
            await dragonflyClient.del(email)
            await pool.query('UPDATE users SET isverified = TRUE WHERE email = $1',[email])
            return res.status(200).json({message:"Your email has been successfully verified"})
        }else{
            return res.status(400).json({message:"Invalid OTP"})
 
        }
        
    } catch (error) {
        console.error(error)
        res.status(500).json({message:'Server error. Please try again later.'})
        
    }
  }
);
export default router