const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Stand = require('../models/Stand');
const { authenticateToken } = require('../middleware/auth');

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    console.log('Henter brugerprofil for ID:', req.session.userId);
    const user = await User.findById(req.session.userId)
      .select('-password')
      .populate('products');
    
    console.log('Fundet bruger:', user);
      
    if (!user) {
      console.log('Bruger ikke fundet');
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    console.log('Returnerer brugerdata med produkter:', user.products);
    res.json(user);
  } catch (error) {
    console.error('Fejl ved hentning af brugerprofil:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af brugerprofil' });
  }
});

// Get dashboard data
router.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    console.log('Henter dashboard data for bruger:', req.session.userId);
    
    // Hent bruger med produkter
    const user = await User.findById(req.session.userId)
      .select('-password')
      .populate('products');

    if (!user) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Hent alle stands for brugeren
    const stands = await Stand.find({ 
      $or: [
        { ownerId: user._id },
        { userId: user._id }
      ]
    });

    console.log('Fundet stands:', stands);

    res.json({
      user,
      stands,
      totalStands: stands.length,
      totalClicks: stands.reduce((sum, stand) => sum + stand.clicks, 0)
    });
  } catch (error) {
    console.error('Fejl ved hentning af dashboard data:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af dashboard data' });
  }
});

module.exports = router; 