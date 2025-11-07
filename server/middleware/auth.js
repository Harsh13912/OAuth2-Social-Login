// server/middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
    // Get token from cookie
    const token = req.cookies.token;

    // Check if no token
    if (!token) {
        return res.status(401).json({ error: 'No token, authorization denied' });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Add user id to request
        req.userId = decoded.id;
        next();
    } catch (err) {
        console.error('Token verification error:', err);
        res.status(401).json({ error: 'Token is not valid' });
    }
};