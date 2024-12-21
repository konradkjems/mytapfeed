const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const upload = require('../config/multer');
const cloudinary = require('../config/cloudinary');
const LandingPage = require('../models/LandingPage');

// Landing Pages endpoints
router.post('/', authenticateToken, upload.fields([
  { name: 'logo', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('Modtaget landing page data:', req.body);
    console.log('Modtaget filer:', req.files);
    
    const { 
      title, 
      description, 
      backgroundColor, 
      buttonColor, 
      buttonTextColor,
      titleColor,
      descriptionColor,
      buttons,
      showTitle,
      socialLinks 
    } = req.body;
    
    // Upload billeder til Cloudinary hvis de findes
    let logoUrl = null;
    let backgroundImageUrl = null;

    if (req.files.logo) {
      const logoResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { folder: 'landing-pages/logos' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.files.logo[0].buffer);
      });
      logoUrl = logoResult.secure_url;
    }

    if (req.files.backgroundImage) {
      const backgroundResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { folder: 'landing-pages/backgrounds' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.files.backgroundImage[0].buffer);
      });
      backgroundImageUrl = backgroundResult.secure_url;
    }

    const page = new LandingPage({
      userId: req.session.userId,
      title,
      description,
      logo: logoUrl,
      backgroundImage: backgroundImageUrl,
      backgroundColor,
      buttonColor,
      buttonTextColor,
      titleColor,
      descriptionColor,
      buttons: JSON.parse(buttons || '[]'),
      showTitle: showTitle === 'true',
      socialLinks: JSON.parse(socialLinks || '{}')
    });

    console.log('Gemmer landing page:', page);

    await page.save();
    res.status(201).json(page);
  } catch (error) {
    console.error('Fejl ved oprettelse af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved oprettelse af landing page' });
  }
});

router.get('/', authenticateToken, async (req, res) => {
  try {
    const pages = await LandingPage.find({ userId: req.session.userId });
    res.json(pages);
  } catch (error) {
    console.error('Fejl ved hentning af landing pages:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing pages' });
  }
});

// Preview endpoint
router.get('/preview/:id', async (req, res) => {
  try {
    console.log('Henter preview for landing page:', req.params.id);
    const page = await LandingPage.findById(req.params.id);
    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }
    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page preview:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

router.put('/:id', authenticateToken, upload.fields([
  { name: 'logo', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('Modtaget opdateringsdata:', req.body);
    console.log('Modtaget filer:', req.files);
    
    const { 
      title, 
      description, 
      backgroundColor, 
      buttonColor, 
      buttonTextColor, 
      titleColor,
      descriptionColor,
      buttons, 
      showTitle, 
      socialLinks 
    } = req.body;
    
    const updates = {
      title,
      description,
      backgroundColor,
      buttonColor,
      buttonTextColor,
      titleColor,
      descriptionColor,
      buttons: JSON.parse(buttons || '[]'),
      showTitle: showTitle === 'true',
      socialLinks: JSON.parse(socialLinks || '{}')
    };

    if (req.files?.logo) {
      const logoResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { folder: 'landing-pages/logos' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.files.logo[0].buffer);
      });
      updates.logo = logoResult.secure_url;
    }

    if (req.files?.backgroundImage) {
      const backgroundResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { folder: 'landing-pages/backgrounds' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.files.backgroundImage[0].buffer);
      });
      updates.backgroundImage = backgroundResult.secure_url;
    }

    console.log('Opdaterer landing page med:', updates);

    const page = await LandingPage.findOneAndUpdate(
      { _id: req.params.id, userId: req.session.userId },
      updates,
      { new: true }
    );

    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }

    console.log('Opdateret landing page:', page);
    res.json(page);
  } catch (error) {
    console.error('Fejl ved opdatering af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved opdatering af landing page' });
  }
});

router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const page = await LandingPage.findOneAndDelete({
      _id: req.params.id,
      userId: req.session.userId
    });

    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }

    // Slet billeder fra Cloudinary
    if (page.logo) {
      const logoPublicId = page.logo.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`landing-pages/logos/${logoPublicId}`);
    }

    if (page.backgroundImage) {
      const bgPublicId = page.backgroundImage.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`landing-pages/backgrounds/${bgPublicId}`);
    }

    res.json({ message: 'Landing page slettet succesfuldt' });
  } catch (error) {
    console.error('Fejl ved sletning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved sletning af landing page' });
  }
});

// Public endpoint til at vise landing pages
router.get('/view/:id', async (req, res) => {
  try {
    console.log('Modtaget anmodning om landing page med ID:', req.params.id);
    
    const page = await LandingPage.findById(req.params.id);
    console.log('Fundet landing page:', page);
    
    if (!page) {
      console.log('Landing page ikke fundet');
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }
    
    console.log('Sender landing page data');
    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

module.exports = router; 