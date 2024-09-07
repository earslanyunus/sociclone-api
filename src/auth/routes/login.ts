import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";

const router = express.Router();

router.post("/", (req: express.Request, res: express.Response, next: express.NextFunction) => {
  passport.authenticate("local", { session: false }, (err: Error | null, user: any, info: { message: string } | undefined) => {
    if (err || !user) {
      return res.status(400).json({
        message: info ? info.message : "Giriş başarısız",
        user: user,
      });
    }
    req.login(user, { session: false }, (err) => {
      if (err) {
        res.send(err);
      }
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET as string,{expiresIn:"1d"});
      res.cookie("token", token, { httpOnly: true, secure: true });
      return res.json({ user });
    });
  })(req, res);
});

export default router;
