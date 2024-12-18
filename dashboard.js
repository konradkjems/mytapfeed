const express = require('express');
const router = express.Router();

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ message: 'Ikke autoriseret', redirect: '/login' });
    }
}

// Dashboard data endpoint
router.get('/status', requireAuth, (req, res) => {
    res.json({
        username: req.session.username,
        message: 'Velkommen til dashboard',
        userInfo: {
            username: req.session.username
        }
    });
});

// Logout endpoint
router.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Fejl ved logout' });
        }
        res.json({ success: true, message: 'Logout succesfuldt', redirect: '/login' });
    });
});

// Opdater stands routes til products
router.post('/products', requireAuth, async (req, res) => {
    try {
        const { name, location, description } = req.body;
        const productsCollection = req.app.locals.db.collection("products");
        
        const newProduct = {
            name,
            location,
            description,
            userId: req.session.userId,
            createdAt: new Date(),
            status: 'active'
        };

        const result = await productsCollection.insertOne(newProduct);
        
        res.status(201).json({
            success: true,
            message: 'Produkt tilføjet succesfuldt',
            productId: result.insertedId
        });

    } catch (error) {
        console.error('Fejl ved tilføjelse af produkt:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Der opstod en fejl ved tilføjelse af produktet' 
        });
    }
});

router.get('/products', requireAuth, async (req, res) => {
    try {
        const productsCollection = req.app.locals.db.collection("products");
        const products = await productsCollection.find({ userId: req.session.userId }).toArray();
        
        res.json({
            success: true,
            products
        });

    } catch (error) {
        console.error('Fejl ved hentning af produkter:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Der opstod en fejl ved hentning af produkter' 
        });
    }
});

module.exports = router; 