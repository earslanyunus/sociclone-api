import { Router } from "express";

const router = Router();

router.get("/", (req, res) => {
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.status(200).json({ message: "Signout successful" });
});

export default router;