import jwt from 'jsonwebtoken'
import { config } from 'dotenv'
const { verify } = jwt
config()

export const verifyToken = (...allowedRoles) => {
    return (req, res, next) => {
        try {

            console.log("COOKIES:", req.cookies);
            console.log("TOKEN:", req.cookies?.token);
            console.log("SECRET:", process.env.SECRET_KEY);

            const token = req.cookies?.token

            if (!token) {
                return res.status(401).json({ message: "Please login first" })
            }

            let decodedToken = verify(token, process.env.SECRET_KEY)

            console.log("DECODED:", decodedToken);

            if (!allowedRoles.includes(decodedToken.role)) {
                return res.status(403).json({ message: "You are not authorized" })
            }

            req.user = decodedToken

            next()

        } catch (err) {

            console.log("VERIFY ERROR:", err);

            res.status(401).json({ message: "Invalid token" })
        }
    }
}