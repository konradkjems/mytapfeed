const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authenticateToken = async (req, res, next) => {
    try {
        // Tjek om brugeren har en aktiv session
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ message: 'Ikke autoriseret' });
        }

        // Find brugeren i databasen
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(401).json({ message: 'Bruger ikke fundet' });
        }

        // Sæt bruger på request objektet
        req.user = user;
        next();
    } catch (error) {
        console.error('Fejl i authenticateToken middleware:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved autentificering' });
    }
};

const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ message: 'Ikke autoriseret' });
    }
    next();
};

const isAdmin = async (req, res, next) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ message: 'Ikke autoriseret' });
        }

        const user = await User.findById(req.session.userId);
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: 'Ingen adgang' });
        }

        next();
    } catch (error) {
        console.error('Fejl i isAdmin middleware:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved tjek af admin rettigheder' });
    }
};

module.exports = {
    authenticateToken,
    requireAuth,
    isAdmin
}; 