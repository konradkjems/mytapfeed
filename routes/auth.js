const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User');
const Stand = require('../models/Stand');

// Login route
router.post('/login', async (req, res) => {
  try {
    const { username, password, standerId } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ message: 'Ugyldigt brugernavn eller adgangskode' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Ugyldigt brugernavn eller adgangskode' });
    }

    // Gem bruger info i session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.isAdmin = user.isAdmin;

    let activatedStand = null;

    // Hvis der er et standerId, aktiver produktet
    if (standerId) {
      console.log('Forsøger at aktivere produkt med ID:', standerId);
      const stand = await Stand.findOne({ standerId });
      console.log('Fundet produkt:', stand);
      
      if (stand && stand.status === 'unclaimed') {
        console.log('Produktet er unclaimed, opdaterer status...');
        stand.status = 'claimed';
        stand.ownerId = user._id;
        stand.userId = user._id;
        stand.claimedAt = new Date();
        await stand.save();
        console.log('Produkt opdateret:', stand);

        // Tilføj produktet til brugerens products array
        console.log('Tilføjer produkt til bruger...');
        console.log('Bruger før opdatering:', user);
        user.products = user.products || [];
        user.products.push(stand._id);
        await user.save();
        console.log('Bruger efter opdatering:', user);
        
        activatedStand = stand;
      } else {
        console.log('Produkt er enten ikke fundet eller allerede claimed');
      }
    }

    // Gem session før vi sender response
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        resolve();
      });
    });

    // Hent den opdaterede bruger med produkter
    const updatedUser = await User.findById(user._id)
      .select('-password')
      .populate('products');

    res.json({ 
      message: 'Login succesfuldt',
      user: updatedUser,
      activatedStand
    });
  } catch (error) {
    console.error('Login fejl:', error);
    res.status(500).json({ message: 'Der opstod en fejl under login' });
  }
});

// Register route
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, standerId } = req.body;

    // Tjek om brugernavn eller email allerede eksisterer
    const existingUser = await User.findOne({ 
      $or: [
        { username: username },
        { email: email }
      ]
    });

    if (existingUser) {
      return res.status(400).json({ 
        message: 'Brugernavn eller email er allerede i brug' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Opret ny bruger
    const user = new User({
      username,
      email,
      password: hashedPassword,
      products: [] // Initialiser products array
    });

    await user.save();

    // Gem bruger info i session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.isAdmin = user.isAdmin;

    let activatedStand = null;

    // Hvis der er et standerId, aktiver produktet
    if (standerId) {
      console.log('Forsøger at aktivere produkt med ID:', standerId);
      const stand = await Stand.findOne({ standerId });
      console.log('Fundet produkt:', stand);
      
      if (stand && stand.status === 'unclaimed') {
        console.log('Produktet er unclaimed, opdaterer status...');
        stand.status = 'claimed';
        stand.ownerId = user._id;
        stand.userId = user._id;
        stand.claimedAt = new Date();
        await stand.save();
        console.log('Produkt opdateret:', stand);

        // Tilføj produktet til brugerens products array
        console.log('Tilføjer produkt til bruger...');
        console.log('Bruger før opdatering:', user);
        user.products = user.products || [];
        user.products.push(stand._id);
        await user.save();
        console.log('Bruger efter opdatering:', user);
        
        activatedStand = stand;
      } else {
        console.log('Produkt er enten ikke fundet eller allerede claimed');
      }
    }

    // Gem session før vi sender response
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        resolve();
      });
    });

    // Hent den opdaterede bruger med produkter
    const updatedUser = await User.findById(user._id)
      .select('-password')
      .populate('products');

    res.status(201).json({ 
      message: 'Bruger oprettet succesfuldt',
      user: updatedUser,
      activatedStand
    });
  } catch (error) {
    console.error('Registreringsfejl:', error);
    res.status(500).json({ message: 'Der opstod en fejl under registrering' });
  }
});

// Logout route
router.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: 'Der opstod en fejl under logout' });
    }
    res.json({ message: 'Logout succesfuldt' });
  });
});

// Check auth status route
router.get('/status', (req, res) => {
  if (req.session.userId) {
    res.json({ 
      isAuthenticated: true,
      user: {
        id: req.session.userId,
        username: req.session.username,
        isAdmin: req.session.isAdmin
      }
    });
  } else {
    res.json({ 
      isAuthenticated: false,
      user: null
    });
  }
});

module.exports = router; 