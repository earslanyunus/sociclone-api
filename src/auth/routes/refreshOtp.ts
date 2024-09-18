import { Request, Response, Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();


router.get("/", async (req: Request, res: Response) => {
    const { refresh_token } = req.cookies;
    if (!refresh_token) {
        return res.status(400).json({ message: "Refresh token is required" });
    }
    try {
        const decoded = jwt.verify(refresh_token, process.env.JWT_SECRET as string) as { id: string };
        const access_token = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET as string, { expiresIn: "15m", issuer: process.env.JWT_ISSUER, audience: process.env.JWT_AUDIENCE, subject: decoded.id });
        res.cookie("access_token", access_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== "development",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000,
        });
        return res.status(200).json({ message: "Access token refreshed" });
    } catch (error) {
        return res.status(401).json({ message: "Invalid refresh token" });
    }
});

export default router;