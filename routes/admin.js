const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Stand = require('../models/Stand');
const LandingPage = require('../models/LandingPage');
const { requireAuth, isAdmin } = require('../middleware/auth');

// Hent admin statistik
router.get('/statistics', requireAuth, isAdmin, async (req, res) => {
  try {
    // Hent bruger statistik
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ lastLogin: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
    
    // Hent produkt statistik
    const totalStands = await Stand.countDocuments();
    const claimedStands = await Stand.countDocuments({ status: 'active' });
    
    // Hent klik statistik
    const allStands = await Stand.find();
    const totalClicks = allStands.reduce((sum, stand) => sum + (stand.clicks || 0), 0);
    const averageClicksPerStand = totalClicks / (totalStands || 1);

    // Hent landing page statistik
    const totalLandingPages = await LandingPage.countDocuments();
    const averageLandingPagesPerUser = totalLandingPages / (totalUsers || 1);

    // Hent produkt type fordeling
    const productTypeDistribution = await Stand.aggregate([
      { $group: { _id: '$productType', count: { $sum: 1 } } }
    ]);
    const productTypes = {};
    productTypeDistribution.forEach(type => {
      productTypes[type._id] = type.count;
    });

    // Hent signups over tid (sidste 30 dage)
    const signupsOverTime = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id': 1 } }
    ]);
    const signupsData = {};
    signupsOverTime.forEach(day => {
      signupsData[day._id] = day.count;
    });

    // Hent klik over tid (sidste 30 dage)
    const clicksOverTime = await Stand.aggregate([
      {
        $unwind: '$clickHistory'
      },
      {
        $match: {
          'clickHistory.timestamp': { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$clickHistory.timestamp' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id': 1 } }
    ]);
    const clicksData = {};
    clicksOverTime.forEach(day => {
      clicksData[day._id] = day.count;
    });

    res.json({
      users: {
        total: totalUsers,
        active: activeUsers,
        signupsOverTime: signupsData
      },
      stands: {
        total: totalStands,
        claimed: claimedStands,
        averageClicksPerStand: Math.round(averageClicksPerStand * 100) / 100,
        productTypeDistribution: productTypes
      },
      content: {
        totalLandingPages,
        averageLandingPagesPerUser: Math.round(averageLandingPagesPerUser * 100) / 100
      },
      engagement: {
        totalClicks,
        clicksOverTime: clicksData
      }
    });
  } catch (error) {
    console.error('Fejl ved hentning af admin statistik:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af statistik' });
  }
});

// Hent claimed produkter
router.get('/stands/claimed', requireAuth, isAdmin, async (req, res) => {
  try {
    const claimedProducts = await Stand.find({ status: 'active' })
      .populate('user', 'username')
      .populate('landingPage', 'title')
      .sort('-claimedAt');

    const productsWithStats = claimedProducts.map(product => ({
      _id: product._id,
      standerId: product.standerId,
      productType: product.productType,
      user: {
        _id: product.user._id,
        username: product.user.username
      },
      claimedAt: product.claimedAt,
      views: product.clicks || 0,
      lastViewedAt: product.lastClickAt,
      landingPage: product.landingPage ? {
        _id: product.landingPage._id,
        title: product.landingPage.title
      } : null
    }));

    res.json(productsWithStats);
  } catch (error) {
    console.error('Fejl ved hentning af claimed produkter:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af claimed produkter' });
  }
});

module.exports = router; 