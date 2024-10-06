import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import argon2 from "argon2";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import prisma from "./prisma";

passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await prisma.user.findUnique({
          where: { email: email },
        });
        if (!user) {
          return done(null, false, { message: "User not found" });
        }
        const {
          username,
          password: hashedPassword,
          email: userEmail,
          isVerified,
          name,
          type
        } = user;
        if (!isVerified) {
          return done(null, false, { message: "User not verified" });
        }
        const isValid = await argon2.verify(hashedPassword, password);
        if (!isValid) {
          return done(null, false, { message: "Invalid password" });
        }
        return done(null, { username, email, name,type });
      } catch (error) {
        console.error("Passport authentication error:", error);
        return done(error);
      }
    }
  )
);

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET as string,
};
passport.use(
  new JwtStrategy(jwtOptions, async (payload , done) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: payload.id },
        });
        if(user){
            return done(null,user)
        }else{
            return done(null,false)
        }

    } catch (error) {
      return done(error);
    }
  })
);

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID as string,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
  callbackURL: '/auth/google/callback'
},
async (accessToken: any, refreshToken: any, profile: any, done: any) => {
  try {
    const user = await prisma.user.findUnique({
      where: { email: profile.emails[0].value },
    });
    if(user){
      return done(null,user)


    }else{
      const newUser = await prisma.user.create({
        data:{
          username:profile.displayName,
          email:profile.emails[0].value,
          name:profile.displayName,
          isVerified:true,
          password:'',
          type:'google'
        }
      })
      return done(null,newUser)
      


    }
  } catch (error) {
    return done(error)
  }
}))


export default passport;
