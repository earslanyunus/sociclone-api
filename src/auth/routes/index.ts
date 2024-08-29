import express from 'express';
import signupRoutes from './signup'

const router = express.Router()

router.use('/signup',signupRoutes)

export default router