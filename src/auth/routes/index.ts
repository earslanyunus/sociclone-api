import express from 'express';
import signupRoute from './signup';
import verifyOtpRoute from './signup-verify';
import resendOtpRoute from './resendOTP';
import loginRoute from './login';
import verifyOTPLoginRoute from './login-verify';
const router = express.Router();

router.use('/signup', signupRoute);
router.use('/signup-verify', verifyOtpRoute);
router.use('/login', loginRoute);
router.use('/login-verify', verifyOTPLoginRoute);
router.use('/resend-otp', resendOtpRoute);

export default router;