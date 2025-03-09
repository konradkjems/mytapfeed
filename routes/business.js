const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const NodeCache = require('node-cache');
const User = require('../models/User');

// Cache konfiguration
const businessCache = new NodeCache({ 
    stdTTL: 1800,  // 30 minutter
    checkperiod: 300,  // Tjek for udløbne keys hvert 5. minut
    deleteOnExpire: false  // Behold udløbne værdier indtil nye er hentet
});

// Cache konfiguration for søgeresultater
const searchCache = new NodeCache({ 
    stdTTL: 300, // 5 minutter
    checkperiod: 60
});

// Rate limiter konfiguration
const placesSearchLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minut
    max: 10, // max 10 requests per minut
    message: { 
        message: 'For mange søgninger. Vent venligst et minut.',
        retryAfter: 60
    }
});

// Rate limiter for Google reviews
const googleReviewsLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minut
    max: 5, // max 5 requests per minut (øget fra 2)
    message: { 
        message: 'For mange anmodninger. Vent venligst et minut.',
        retryAfter: 60
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true // Tæl kun fejlede requests
});

// Søg efter virksomheder
const searchHandler = async (req, res) => {
    try {
        console.log('Business search request modtaget:', {
            query: req.query,
            user: req.session?.userId
        });
        
        const { searchQuery } = req.query;
        
        if (!searchQuery || !searchQuery.trim()) {
            return res.status(400).json({ message: 'Søgeterm er påkrævet' });
        }

        // Tjek cache først
        const cacheKey = `search_${searchQuery.toLowerCase().trim()}`;
        const cachedResults = searchCache.get(cacheKey);
        if (cachedResults) {
            console.log('Returnerer cached søgeresultater for:', searchQuery);
            return res.json({ places: cachedResults });
        }

        if (!process.env.GOOGLE_MAPS_API_KEY) {
            console.error('Google Maps API nøgle mangler');
            return res.status(500).json({ message: 'Google Maps API nøgle er ikke konfigureret' });
        }

        console.log('Søger efter virksomheder med query:', searchQuery);

        try {
            const searchUrl = `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(searchQuery)}&key=${process.env.GOOGLE_MAPS_API_KEY}&language=da&region=dk&type=establishment`;
            const searchResponse = await axios.get(searchUrl);

            console.log('Google Places API svar status:', searchResponse.data.status);

            if (searchResponse.data.status === 'ZERO_RESULTS') {
                return res.json({ places: [] });
            }

            if (searchResponse.data.status === 'REQUEST_DENIED') {
                console.error('Google Places API afviste anmodningen:', searchResponse.data.error_message);
                return res.status(503).json({ 
                    message: 'Kunne ikke søge lige nu, prøv igen senere',
                    error: searchResponse.data.error_message
                });
            }

            if (searchResponse.data.status === 'OVER_QUERY_LIMIT') {
                return res.status(429).json({ 
                    message: 'API kvote overskredet. Prøv igen senere.',
                    retryAfter: 60
                });
            }

            if (!searchResponse.data.results || !Array.isArray(searchResponse.data.results)) {
                console.error('Uventet svar fra Google Places API:', searchResponse.data);
                return res.status(503).json({ 
                    message: 'Uventet svar fra søgetjenesten. Prøv igen senere.'
                });
            }

            const places = searchResponse.data.results.map(place => ({
                placeId: place.place_id,
                name: place.name,
                address: place.formatted_address,
                rating: place.rating,
                userRatingsTotal: place.user_ratings_total,
                types: place.types
            }));

            // Gem resultater i cache
            searchCache.set(cacheKey, places);
            console.log(`Fandt ${places.length} resultater for søgning:`, searchQuery);
            res.json({ places });
        } catch (axiosError) {
            console.error('Axios fejl ved søgning efter virksomheder:', {
                error: axiosError.message,
                response: axiosError.response?.data,
                status: axiosError.response?.status
            });
            
            return res.status(503).json({ 
                message: 'Kunne ikke kontakte søgetjenesten. Prøv igen senere.',
                error: axiosError.message
            });
        }
    } catch (error) {
        console.error('Fejl ved søgning efter virksomheder:', {
            error: error.message,
            stack: error.stack
        });

        res.status(500).json({ 
            message: 'Der opstod en fejl ved søgning. Prøv igen senere.',
            error: error.message
        });
    }
};

// Google reviews handler
const reviewsHandler = async (req, res) => {
    try {
        console.log('Google reviews request modtaget:', {
            userId: req.session?.userId
        });
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            console.log('Bruger ikke fundet:', req.session?.userId);
            return res.status(404).json({ message: 'Bruger ikke fundet' });
        }

        if (!user.googlePlaceId) {
            console.log('Ingen Google Place ID fundet for bruger:', req.session?.userId);
            return res.json({
                business: null,
                reviews: []
            });
        }

        const cacheKey = `reviews_${user.googlePlaceId}`;
        
        // Prøv at hente fra cache først
        let cachedData = businessCache.get(cacheKey);
        
        // Hvis vi har cached data, send det med det samme
        if (cachedData) {
            console.log('Returnerer cached reviews data for:', user.googlePlaceId);
            return res.json(cachedData);
        }

        if (!process.env.GOOGLE_MAPS_API_KEY) {
            console.error('Google Maps API nøgle mangler');
            return res.status(503).json({ 
                message: 'Google Maps API nøgle er ikke konfigureret'
            });
        }

        console.log('Henter Google reviews for place ID:', user.googlePlaceId);

        try {
            // Hvis ingen cache, hent nye data
            const placeDetailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${user.googlePlaceId}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
            
            const placeDetailsResponse = await axios.get(placeDetailsUrl);
            console.log('Google Places API svar status:', placeDetailsResponse.data.status);

            if (placeDetailsResponse.data.status === 'REQUEST_DENIED') {
                console.error('Google Places API afviste anmodningen:', placeDetailsResponse.data.error_message);
                return res.status(503).json({ 
                    message: 'Kunne ikke hente virksomhedsdata lige nu, prøv igen senere',
                    error: placeDetailsResponse.data.error_message
                });
            }

            if (placeDetailsResponse.data.status === 'INVALID_REQUEST') {
                console.error('Ugyldig anmodning til Google Places API:', placeDetailsResponse.data.error_message);
                return res.status(400).json({ 
                    message: 'Ugyldig place ID',
                    error: placeDetailsResponse.data.error_message
                });
            }

            if (!placeDetailsResponse.data.result) {
                console.log('Ingen resultater fundet for place ID:', user.googlePlaceId);
                return res.json({
                    business: null,
                    reviews: []
                });
            }

            const placeDetails = placeDetailsResponse.data.result;
            const responseData = {
                business: {
                    name: placeDetails.name,
                    rating: placeDetails.rating,
                    user_ratings_total: placeDetails.user_ratings_total,
                    place_id: user.googlePlaceId,
                    formatted_address: placeDetails.formatted_address,
                    formatted_phone_number: placeDetails.formatted_phone_number,
                    website: placeDetails.website
                },
                reviews: (placeDetails.reviews || []).map(review => ({
                    ...review,
                    reviewId: review.time.toString()
                }))
            };

            // Gem i cache
            businessCache.set(cacheKey, responseData);
            console.log(`Fandt ${responseData.reviews.length} anmeldelser for place ID:`, user.googlePlaceId);
            res.json(responseData);
        } catch (axiosError) {
            console.error('Axios fejl ved hentning af Google reviews:', {
                error: axiosError.message,
                response: axiosError.response?.data,
                status: axiosError.response?.status
            });
            
            return res.status(503).json({ 
                message: 'Kunne ikke kontakte Google Places API. Prøv igen senere.',
                error: axiosError.message
            });
        }
    } catch (error) {
        console.error('Fejl ved hentning af Google reviews:', {
            error: error.message,
            stack: error.stack
        });

        res.status(500).json({ 
            message: 'Der opstod en fejl ved hentning af anmeldelser. Prøv igen senere.',
            error: error.message
        });
    }
};

// Registrer routes
router.get('/search', authenticateToken, placesSearchLimiter, searchHandler);
router.get('/google-reviews', authenticateToken, googleReviewsLimiter, reviewsHandler);

module.exports = router; 