import express from 'express';
import signupRoute from './signup';
import verifyOtpRoute from './verifyOTP';
import resendOtpRoute from './resendOTP';
import loginRoute from './login';

const router = express.Router();

router.use('/signup', signupRoute);
router.use('/verify-otp', verifyOtpRoute);
router.use('/resend-otp', resendOtpRoute);
router.use('/login', loginRoute);

export default router;