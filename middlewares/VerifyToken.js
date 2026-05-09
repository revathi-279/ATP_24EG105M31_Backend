import jwt from 'jsonwebtoken'
import { config } from 'dotenv'

const { verify } = jwt

config()

export const verifyToken = (...allowedRoles) => {
    return (req, res, next) => {
        try {

            // DEBUG LOGS
            console.log("========== VERIFY TOKEN ==========")
            console.log("COOKIES:", req.cookies)
            console.log("TOKEN:", req.cookies?.token)
            console.log("SECRET_KEY:", process.env.SECRET_KEY)

            // get token from cookie
            const token = req.cookies?.token

            // token missing
            if (!token) {
                console.log("NO TOKEN FOUND")
                return res.status(401).json({
                    message: "Please login first"
                })
            }

            // verify token
            const decodedToken = verify(token, process.env.SECRET_KEY)

            console.log("DECODED TOKEN:", decodedToken)

            // role check
            if (!allowedRoles.includes(decodedToken.role)) {

                console.log("ROLE NOT AUTHORIZED")

                return res.status(403).json({
                    message: "You are not authorized"
                })
            }

            // attach user
            req.user = decodedToken

            console.log("TOKEN VERIFIED SUCCESSFULLY")
            console.log("==================================")

            next()

        } catch (err) {

            console.log("VERIFY ERROR:", err)
            console.log("==================================")

            return res.status(401).json({
                message: "Invalid token"
            })
        }
    }
}