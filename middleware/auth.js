// Auth middleware
const authenticateToken = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Ikke autoriseret' });
    }
    next();
};

module.exports = {
    authenticateToken
}; 