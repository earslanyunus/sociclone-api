import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { pool } from "./db";
import argon2 from "argon2";

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
        } = userDb.rows[0];
        if (!isverified) {
          return done(null, false, { message: "User not verified" });
        }
        const isValid = await argon2.verify(hashedPassword, password);
        if (!isValid) {
          return done(null, false, { message: "Invalid password" });
        }
        return done(null, { username, email, name });
      } catch (error) {
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


export default passport;
