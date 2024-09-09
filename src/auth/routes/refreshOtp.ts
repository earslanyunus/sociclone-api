import { Request, Response, Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();


router.post("/", async (req: Request, res: Response) => {
    const { refresh_token } = req.body;
    if (!refresh_token) {
        return res.status(400).json({ message: "Refresh token is required" });
    }
    try {
        const decoded = jwt.verify(refresh_token, process.env.JWT_SECRET as string) as { id: string };
        const access_token = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET as string, { expiresIn: "15m", issuer: process.env.JWT_ISSUER, audience: process.env.JWT_AUDIENCE, subject: decoded.id });
        
        return res.status(200).json({ access_token });
    } catch (error) {
        return res.status(401).json({ message: "Invalid refresh token" });
    }
});

export default router;