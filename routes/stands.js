const express = require('express');
const router = express.Router();
const Stand = require('../models/Stand');
const { authenticateToken } = require('../middleware/auth');

// Get stand by ID
router.get('/:standerId', async (req, res) => {
  try {
    const stand = await Stand.findOne({ standerId: req.params.standerId });
    
    if (!stand) {
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    // Bestem redirect URL baseret på status
    let redirectUrl;
    if (stand.status === 'unclaimed') {
      redirectUrl = `/unclaimed/${stand.standerId}`;
    } else if (!stand.redirectUrl && !stand.landingPageId) {
      redirectUrl = `/not-configured/${stand.standerId}`;
    } else if (stand.landingPageId) {
      redirectUrl = `/landing/${stand.landingPageId}`;
    } else {
      redirectUrl = stand.redirectUrl;
    }

    res.json({
      ...stand.toObject(),
      redirectUrl
    });
  } catch (error) {
    console.error('Fejl ved hentning af stand:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af stand' });
  }
});

// Get all stands for user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const stands = await Stand.find({ ownerId: req.session.userId });
    res.json(stands);
  } catch (error) {
    console.error('Fejl ved hentning af stands:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af stands' });
  }
});

// Update stand
router.put('/:standerId', authenticateToken, async (req, res) => {
  try {
    const stand = await Stand.findOne({ 
      standerId: req.params.standerId,
      ownerId: req.session.userId
    });

    if (!stand) {
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    const updates = req.body;
    Object.keys(updates).forEach(key => {
      stand[key] = updates[key];
    });

    await stand.save();
    res.json(stand);
  } catch (error) {
    console.error('Fejl ved opdatering af stand:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved opdatering af stand' });
  }
});

// Record click
router.post('/:standerId/click', async (req, res) => {
  try {
    const stand = await Stand.findOne({ standerId: req.params.standerId });
    
    if (!stand) {
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    stand.clicks += 1;
    stand.clickHistory.push({ timestamp: new Date() });
    await stand.save();

    res.json({ message: 'Klik registreret' });
  } catch (error) {
    console.error('Fejl ved registrering af klik:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved registrering af klik' });
  }
});

module.exports = router; 