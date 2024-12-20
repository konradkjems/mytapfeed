// ... existing code ...

// Endpoint til at hente en specifik landing page
app.get('/api/landing-pages/:id', async (req, res) => {
  try {
    const landingPage = await LandingPage.findById(req.params.id);
    if (!landingPage) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }
    res.json(landingPage);
  } catch (error) {
    console.error('Fejl ved hentning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

// ... rest of the code ... 