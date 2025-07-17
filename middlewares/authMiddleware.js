// middlewares/authMiddleware.js

const jwt = require("jsonwebtoken");
const User = require("../models/User");

exports.protect = async (req, res, next) => {
  let token;
  let secret;

  if (req.headers.authorization?.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
    secret = process.env.JWT_SECRET;
  } else if (req.cookies?.refreshToken) {
    token = req.cookies.refreshToken;
    secret = process.env.REFRESH_TOKEN_SECRET;
  }

  if (!token) return res.status(401).json({ message: "Not authorized, token missing" });

  try {
    const decoded = jwt.verify(token, secret);
    req.user = await User.findById(decoded.id).select("-password");
    if (!req.user) throw new Error("User not found");
    next();
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Token failed or expired" });
  }
};
