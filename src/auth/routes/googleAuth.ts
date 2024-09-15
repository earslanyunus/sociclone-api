import { Router } from "express";
import passport from "passport";
import jwt from "jsonwebtoken";

const router = Router()

router.get('/',passport.authenticate('google',{scope:['profile','email'],session:false}))

router.get('/callback',passport.authenticate('google',{failureRedirect:'http://localhost:3001/signin',session:false}), async (req,res)=>{
    if (req.user) {
        const user = req.user as { id: string, email: string, name: string };
        const accessToken = jwt.sign(
          { userId: user.id, email: user.email },
          process.env.JWT_SECRET as string,
          { expiresIn: '15m', issuer: process.env.JWT_ISSUER, audience: process.env.JWT_AUDIENCE }
        );
        const refreshToken = jwt.sign(
          { userId: user.id },
          process.env.JWT_REFRESH_SECRET as string,
          { expiresIn: '7d', issuer: process.env.JWT_ISSUER, audience: process.env.JWT_AUDIENCE }
        );
    
        res.cookie('access_token', accessToken, { 
          httpOnly: true, 
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax'
        });
        res.cookie('refresh_token', refreshToken, { 
          httpOnly: true, 
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax'
        });        res.redirect('http://localhost:3000/home'); // Veya kullanıcıyı başka bir sayfaya yönlendirebilirsiniz
      } else {
        res.redirect('http://localhost:3000/signin');
      }})

export default router