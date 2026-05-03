import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

export const protectedRoute = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided" });
        }       

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if(!decoded ) {
            return res.status(401).json({ error: "Unauthorized: Invalid token" });
        }
        const user = await User.findById(decoded.id).select("-password");

        if (!user) {
            return res.status(401).json({ error : "user not found" });
        }
        req.user = user;
        next();
    } catch (error) {
        console.log("Error in protectedRoute middleware:", error.message);
        res.status(500).json({ error: error.message || "Internal Server Error" });
    }
};