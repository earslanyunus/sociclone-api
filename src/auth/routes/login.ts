import express from "express";
import passport from "passport";
import { body, validationResult } from "express-validator";
import dragonflyClient from "../../config/dragonfly";
import { sendOTPEmail } from "../../config/mail";
import argon2 from "argon2";
import { argon2Config } from "../../config/argon2_config";
const router = express.Router();

router.post(
  "/",
  [
    body("email").isEmail().withMessage("Enter a valid email address"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    passport.authenticate(
      "local",
      { session: false },
      async (
        err: Error | null,
        user: any,
        info: { message: string } | undefined
      ) => {
        if (err || !user) {
          return res.status(400).json({
            message: info ? info.message : "Check your credentials",
          });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await argon2.hash(otp,argon2Config);

        await dragonflyClient.setEx(`login_otp:${user.email}`, 300, hashedOtp); 

        await sendOTPEmail(user.email, otp);

        res.json({ message: "OTP sent", email: user.email });
      }
    )(req, res, next);
  }
);

export default router;
