import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { pool } from "./db";
import argon2 from "argon2";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const userDb = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        if (userDb.rows.length === 0) {
          return done(null, false, { message: "User not found" });
        }
        const {
          username,
          password: hashedPassword,
          email: userEmail,
          isverified,
          name,
          type
        } = userDb.rows[0];
        if (!isverified) {
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
        const userDb = await pool.query('SELECT * FROM users WHERE id = $1',[payload.id])
        if(userDb.rows.length>0){
            return done(null,userDb.rows[0])
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
    const userDb = await pool.query('SELECT * FROM users WHERE email = $1',[profile.emails[0].value])
    if(userDb.rows.length>0){
      return done(null,userDb.rows[0])


    }else{
      const newUser = await pool.query('INSERT INTO users (username,email,name,isverified,password,type) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',[profile.displayName,profile.emails[0].value,profile.displayName,true,'','google'])
      return done(null,newUser.rows[0])
      


    }
  } catch (error) {
    return done(error)
  }
}))


export default passport;
