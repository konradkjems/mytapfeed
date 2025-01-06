// Middleware til at tjekke om brugeren er logget ind
const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ message: 'Ikke autoriseret' });
    }
    next();
};

// Middleware til at tjekke om brugeren er admin
const isAdmin = async (req, res, next) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ message: 'Ikke autoriseret' });
        }

        const User = require('../models/User');
        const user = await User.findById(req.session.userId);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: 'Ingen adgang' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Fejl i admin auth middleware:', error);
        res.status(500).json({ message: 'Der opstod en fejl' });
    }
};

module.exports = {
    requireAuth,
    isAdmin
}; 