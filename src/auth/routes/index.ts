import express from 'express';
import signupRoute from './signup';
import verifyOtpRoute from './signup-verify';
import resendOtpRoute from './resendOTP';
import loginRoute from './login';
import verifyOTPLoginRoute from './login-verify';
import forgotpasswordPart1Route from './forgotpassword-part1';
import forgotpasswordPart2Route from './forgotpassword-part2';
import forgotpasswordPart3Route from './forgotpassword-part3';

const router = express.Router();

router.use('/signup', signupRoute);
router.use('/signup-verify', verifyOtpRoute);
router.use('/login', loginRoute);
router.use('/login-verify', verifyOTPLoginRoute);
router.use('/resend-otp', resendOtpRoute);
router.use('/forgotpassword-part1', forgotpasswordPart1Route);
router.use('/forgotpassword-part2', forgotpasswordPart2Route);
router.use('/forgotpassword-part3', forgotpasswordPart3Route);





export default router;