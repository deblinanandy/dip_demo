import jwt from 'jsonwebtoken';

// Define your JWT secret key here
const JWT_SECRET = 'your_jwt_secret_key_here';

// Middleware to verify the JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Failed to authenticate token' });
        }

        // If everything is good, save the decoded information to request for use in other routes
        req.userId = decoded.id;
        req.email = decoded.email;
        req.role = decoded.role;
        next();
    });
};

export default verifyToken;
