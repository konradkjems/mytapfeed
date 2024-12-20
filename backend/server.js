// ... existing code ...

// Endpoint til at hente en specifik landing page
app.get('/api/landing-pages/:id', async (req, res) => {
  try {
    console.log('Henter landing page med ID:', req.params.id);
    const landingPage = await LandingPage.findById(req.params.id);
    console.log('Fundet landing page:', landingPage);
    
    if (!landingPage) {
      console.log('Landing page ikke fundet');
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }
    
    res.json(landingPage);
  } catch (error) {
    console.error('Detaljeret fejl ved hentning af landing page:', {
      error: error.message,
      stack: error.stack,
      id: req.params.id
    });
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

// ... rest of the code ... 