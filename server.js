require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const { ObjectId } = mongoose.Types;
const User = require('./models/User');
const Stand = require('./models/Stand');
const ResetToken = require('./models/ResetToken');
const passwordResetRouter = require('./routes/passwordReset');
const MongoStore = require('connect-mongo');
const Category = require('./models/Category');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // begrænser upload størrelse til 5MB
    }
});
const cloudinary = require('./config/cloudinary');
const fs = require('fs');
const util = require('util');
const unlinkFile = util.promisify(fs.unlink);
const axios = require('axios');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const google = require('googleapis');
const path = require('path');
const { Client } = require('@googlemaps/google-maps-services-js');
const LandingPage = require('./models/LandingPage');

// Cache konfiguration
const businessCache = new NodeCache({ 
    stdTTL: 600,  // Øg til 10 minutter
    checkperiod: 120  // Tjek for udløbne keys hvert 2. minut
});

// Rate limiter konfiguration
const googleBusinessLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minut
    max: 2, // Reducer til max 2 requests per minut per IP
    message: { 
        message: 'For mange forsøg. Vent venligst et minut før du prøver igen.',
        needsAuth: false,
        retryAfter: 60
    },
    standardHeaders: true,
    legacyHeaders: false
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

// Cache konfiguration for søgeresultater
const searchCache = new NodeCache({ 
    stdTTL: 300, // 5 minutter
    checkperiod: 60
});

console.log('Cloudinary Environment Variables:', {
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key_exists: !!process.env.CLOUDINARY_API_KEY,
    api_secret_exists: !!process.env.CLOUDINARY_API_SECRET
});

console.log('Server starter med miljø:', {
    nodeEnv: process.env.NODE_ENV,
    mongoDbUri: process.env.MONGODB_URI?.substring(0, 20) + '...',
    hasGoogleCreds: !!process.env.GOOGLE_CLIENT_ID && !!process.env.GOOGLE_CLIENT_SECRET,
    hasCloudinaryCreds: !!process.env.CLOUDINARY_API_KEY
});

let app;
if (!app) {
    app = express();
}

// Middleware setup
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://my.tapfeed.dk', 'https://api.tapfeed.dk']
        : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Cookie', 'Origin'],
    exposedHeaders: ['Set-Cookie'],
    preflightContinue: false,
    optionsSuccessStatus: 204
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key', 
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        ttl: 24 * 60 * 60,
        autoRemove: 'native',
        touchAfter: 24 * 3600
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        domain: process.env.NODE_ENV === 'production' ? '.tapfeed.dk' : undefined
    }
}));

// Initialize Passport and restore authentication state from session
app.use(passport.initialize());
app.use(passport.session());

// Debug middleware for sessions
app.use((req, res, next) => {
    console.log('Session Debug:', {
        sessionID: req.sessionID,
        isAuthenticated: req.isAuthenticated(),
        user: req.user,
        session: req.session
    });
    next();
});

// Passport configuration
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Basic routes
app.get('/', (req, res) => {
    res.json({ message: 'Velkommen til TapFeed API' });
});

app.get('/api', (req, res) => {
    res.json({ message: 'TapFeed API er kørende' });
});

// Auth routes
app.get('/api/auth/status', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ 
            isAuthenticated: true, 
            user: req.user 
        });
    } else {
        res.json({ 
            isAuthenticated: false 
        });
    }
});

app.get('/api/auth/google',
    passport.authenticate('google', { 
        scope: ['profile', 'email']
    })
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { 
        failureRedirect: process.env.NODE_ENV === 'production' ? 'https://my.tapfeed.dk/login' : 'http://localhost:3001/login',
        failureMessage: true
    }),
    function(req, res) {
        console.log('Google callback success:', {
            user: req.user,
            session: req.session
        });
        
        // Gem bruger ID i session
        req.session.userId = req.user._id;
        
        // Gem session explicit før redirect
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.redirect(process.env.NODE_ENV === 'production' ? 'https://my.tapfeed.dk/login' : 'http://localhost:3001/login');
            }
            res.redirect(process.env.NODE_ENV === 'production' ? 'https://my.tapfeed.dk/dashboard' : 'http://localhost:3001/dashboard');
        });
    }
);

app.post('/api/auth/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ 
                message: 'Der opstod en fejl ved logout' 
            });
        }
        res.json({ message: 'Logget ud' });
    });
});

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production'
        ? "https://api.tapfeed.dk/api/auth/google/callback"
        : "http://localhost:3000/api/auth/google/callback"
},
async function(accessToken, refreshToken, profile, cb) {
    try {
        console.log('Google Strategy callback:', {
            profile_id: profile.id,
            email: profile.emails[0].value
        });

        let user = await User.findOne({ email: profile.emails[0].value });
        
        if (!user) {
            user = new User({
                username: profile.displayName.toLowerCase().replace(/\s+/g, '_'),
                email: profile.emails[0].value,
                password: 'google-auth-' + Math.random().toString(36).slice(-8),
                googleId: profile.id
            });
            await user.save();
            console.log('New user created:', user._id);
        } else {
            console.log('Existing user found:', user._id);
        }
        
        return cb(null, user);
    } catch (error) {
        console.error('Google Strategy error:', error);
        return cb(error, null);
    }
}));

// Google Business OAuth strategy
passport.use('google-business', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production'
        ? "https://api.tapfeed.dk/api/auth/google-business/callback"
        : "http://localhost:3000/api/auth/google-business/callback",
    scope: [
        'profile', 
        'email',
        'https://www.googleapis.com/auth/business.manage'
    ]
}, async function(accessToken, refreshToken, profile, cb) {
    try {
        console.log('Google Business OAuth callback:', {
            accessToken: accessToken?.substring(0, 20) + '...',
            hasRefreshToken: !!refreshToken,
            profileId: profile.id,
            email: profile.emails[0].value
        });

        // Find bruger baseret på session eller email
        let user;
        if (this.req && this.req.session && this.req.session.userId) {
            user = await User.findById(this.req.session.userId);
        }
        if (!user) {
            user = await User.findOne({ email: profile.emails[0].value });
        }
        
        if (!user) {
            user = new User({
                username: profile.displayName.toLowerCase().replace(/\s+/g, '_'),
                email: profile.emails[0].value,
                password: 'google-auth-' + Math.random().toString(36).slice(-8),
                googleId: profile.id,
                googleAccessToken: accessToken,
                googleRefreshToken: refreshToken
            });
            await user.save();
            console.log('Ny bruger oprettet med Google Business:', user._id);
        } else {
            // Opdater tokens
            user.googleAccessToken = accessToken;
            user.googleRefreshToken = refreshToken;
            await user.save();
            console.log('Eksisterende bruger opdateret med nye tokens:', user._id);
        }
        
        return cb(null, user);
    } catch (error) {
        console.error('Fejl i Google Business OAuth callback:', {
            error: error.message,
            stack: error.stack
        });
        return cb(error, null);
    }
}));

// Debug middleware
app.use((req, res, next) => {
    console.log('Request:', {
        method: req.method,
        path: req.path,
        sessionId: req.sessionID,
        userId: req.session?.userId,
        body: req.body,
        user: req.user
    });
    next();
});

// Google auth routes
app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: 'http://localhost:3001/login' }),
    function(req, res) {
        req.session.userId = req.user._id;
        res.redirect('http://localhost:3001/dashboard');
    }
);

// Google Business auth routes
const googleBusinessScopes = [
    'https://www.googleapis.com/auth/business.manage',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
];

app.get('/api/auth/google-business', (req, res) => {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.NODE_ENV === 'production'
            ? 'https://api.tapfeed.dk/api/auth/google-business/callback'
            : 'http://localhost:3000/api/auth/google-business/callback'
    );

    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: googleBusinessScopes,
        prompt: 'consent'
    });

    console.log('Redirecting til Google OAuth URL:', authUrl);
    res.redirect(authUrl);
});

app.get('/api/auth/google-business/callback', async (req, res) => {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        'http://localhost:3000/api/auth/google-business/callback'
    );

    try {
        console.log('Modtaget OAuth callback med kode');
        const { tokens } = await oauth2Client.getToken(req.query.code);
        console.log('OAuth tokens modtaget:', {
            hasAccessToken: !!tokens.access_token,
            hasRefreshToken: !!tokens.refresh_token,
            expiryDate: tokens.expiry_date
        });

        const user = await User.findById(req.session.userId);
        if (!user) {
            throw new Error('Bruger ikke fundet');
        }

        user.googleAccessToken = tokens.access_token;
        if (tokens.refresh_token) {
            user.googleRefreshToken = tokens.refresh_token;
        }
        await user.save();

        console.log('Tokens gemt for bruger:', user._id);
        res.redirect('/dashboard');
    } catch (error) {
        console.error('OAuth callback fejl:', error);
        res.redirect('/dashboard?error=auth_failed');
    }
});

// Auth endpoints
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find bruger
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
        req.session.isAdmin = user.isAdmin;
        
        // Gem session explicit
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) reject(err);
                resolve();
            });
        });

        res.json({
            message: 'Login succesfuldt',
            user: {
                id: user._id,
                username: user.username,
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        console.error('Login fejl:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.get('/api/auth/status', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            isAuthenticated: true,
            userId: req.session.userId,
            isAdmin: req.session.isAdmin
        });
    } else {
        res.json({ isAuthenticated: false });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout fejl:', err);
            return res.status(500).json({ message: 'Der opstod en fejl under logout' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logout succesfuldt' });
    });
});

// Middleware til at tjekke authentication
const authenticateToken = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Ikke autoriseret' });
    }
    next();
};

// Beskyttede routes
app.use('/api/stands', authenticateToken);

// Protected route middleware
const requireAuth = (req, res, next) => {
    console.log('Session check:', {
        sessionExists: !!req.session,
        userId: req.session?.userId,
        sessionId: req.session?.id
    });

    if (!req.session || !req.session.userId) {
        return res.status(401).json({ message: 'Ikke autoriseret' });
    }
    next();
};

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('MongoDB forbindelse etableret');
    })
    .catch(err => {
        console.error('MongoDB forbindelsesfejl:', err);
    });

// Routes
app.use('/api', passwordResetRouter);

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login forsøg for bruger:', username);
        
        const user = await User.findOne({ username });

        if (!user) {
            console.log('Bruger ikke fundet:', username);
            return res.status(401).json({ message: 'Ugyldigt brugernavn eller adgangskode' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            console.log('Ugyldig adgangskode for bruger:', username);
            return res.status(401).json({ message: 'Ugyldigt brugernavn eller adgangskode' });
        }

        // Gem bruger info i session
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.isAdmin = user.isAdmin;

        console.log('Login succesfuldt:', {
            username: user.username,
            userId: user._id,
            sessionId: req.session.id
        });

        // Gem session før respons sendes
        req.session.save((err) => {
            if (err) {
                console.error('Fejl ved gemning af session:', err);
                return res.status(500).json({ message: 'Der opstod en fejl under login' });
            }

            res.json({ 
                message: 'Login succesfuldt',
                redirect: '/dashboard',
                user: {
                    username: user.username,
                    isAdmin: user.isAdmin
                }
            });
        });
    } catch (error) {
        console.error('Login fejl:', error);
        res.status(500).json({ message: 'Der opstod en fejl under login' });
    }
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    console.log('Registrering forsøgt med:', {
        username: req.body.username,
        email: req.body.email
    });

    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Alle felter skal udfyldes' });
        }

        // Tjek om brugeren allerede eksisterer
        const existingUser = await User.findOne({
            $or: [
                { username: username.toLowerCase() },
                { email: email.toLowerCase() }
            ]
        });

        if (existingUser) {
            console.log('Bruger eksisterer allerede:', existingUser.username);
            return res.status(400).json({
                message: existingUser.username.toLowerCase() === username.toLowerCase()
                    ? 'Brugernavnet er allerede i brug'
                    : 'Email adressen er allerede i brug'
            });
        }

        // Opret ny bruger
        const user = new User({
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password,
            isAdmin: false,
            isBlocked: false
        });

        await user.save();
        console.log('Ny bruger oprettet:', user._id);

        // Log brugeren ind automatisk
        req.session.userId = user._id;
        
        // Gem session explicit
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    console.error('Session gem fejl:', err);
                    reject(err);
                }
                resolve();
            });
        });

        console.log('Session gemt med userId:', req.session.userId);

        res.status(201).json({
            message: 'Bruger oprettet succesfuldt',
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Detaljeret registreringsfejl:', error);
        res.status(500).json({ 
            message: 'Der opstod en fejl under registrering',
            error: error.message 
        });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Fejl ved logout' });
        }
        res.json({ message: 'Logout succesfuldt', redirect: '/login' });
    });
});

// Stands endpoints
app.get('/api/stands', requireAuth, async (req, res) => {
    try {
        const stands = await Stand.find({ userId: req.session.userId })
            .populate('userId', 'username');
        res.json(stands);
    } catch (error) {
        console.error('Fejl ved hentning af stands:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved hentning af stands' });
    }
});

app.post('/api/stands', authenticateToken, async (req, res) => {
    try {
        const stand = new Stand({
            ...req.body,
            userId: req.session.userId
        });
        await stand.save();
        res.status(201).json(stand);
    } catch (error) {
        console.error('Error creating stand:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/stands/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { standerId, redirectUrl, productType, nickname } = req.body;

        console.log('Modtaget opdateringsanmodning:', {
            id,
            standerId,
            redirectUrl,
            productType,
            nickname,
            userId: req.session.userId
        });

        // Find den eksisterende stand først
        const existingStand = await Stand.findOne({ _id: id, userId: req.session.userId });
        
        if (!existingStand) {
            console.log('Stand ikke fundet:', id);
            return res.status(404).json({ message: 'Stander ikke fundet' });
        }

        // Tjek om det nye standerID allerede eksisterer (hvis det er ændret)
        if (standerId !== existingStand.standerId) {
            const duplicateStand = await Stand.findOne({ 
                standerId, 
                _id: { $ne: id } 
            });
            
            if (duplicateStand) {
                console.log('Duplikeret standerID:', standerId);
                return res.status(409).json({ message: 'Stander ID eksisterer allerede' });
            }
        }

        // Opdater standen
        const updatedStand = await Stand.findOneAndUpdate(
            { _id: id, userId: req.session.userId },
            { 
                $set: {
                    standerId,
                    redirectUrl,
                    productType,
                    nickname,
                    updatedAt: new Date()
                }
            },
            { new: true } // Returnerer det opdaterede dokument
        );

        if (!updatedStand) {
            console.log('Kunne ikke opdatere stand:', id);
            return res.status(404).json({ message: 'Kunne ikke opdatere standeren' });
        }

        console.log('Stand opdateret succesfuldt:', updatedStand);
        res.json(updatedStand);

    } catch (error) {
        console.error('Fejl ved opdatering af stand:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved opdatering af stand' });
    }
});

app.delete('/api/stands/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await Stand.deleteOne({ _id: id, userId: req.session.userId });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'Stander ikke fundet' });
        }
        
        res.json({ message: 'Stander slettet succesfuldt' });
    } catch (error) {
        console.error('Fejl ved sletning af stand:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved sletning af stand' });
    }
});

// Admin endpoints
app.get('/api/admin/stands', requireAuth, async (req, res) => {
    try {
        if (!req.session.isAdmin) {
            return res.status(403).json({ message: 'Ikke autoriseret' });
        }

        const stands = await Stand.find().populate('userId', 'username');
        res.json(stands);
    } catch (error) {
        console.error('Admin fejl ved hentning af stands:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved hentning af stands' });
    }
});

// User profile endpoint
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'Bruger ikke fundet' });
        }
        res.json(user);
    } catch (error) {
        console.error('Fejl ved hentning af brugerprofil:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

// Profile image upload endpoint
app.post('/api/user/profile-image', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'Ingen fil uploadet' });
        }

        // Upload buffer direkte til Cloudinary
        const result = await cloudinary.uploader.upload_stream({
            folder: 'profile-images',
            transformation: [
                { width: 300, height: 300, crop: 'fill' }
            ]
        }).end(req.file.buffer);

        // Opdater bruger med nyt billede URL
        const user = await User.findByIdAndUpdate(
            req.session.userId,
            { profileImage: result.secure_url },
            { new: true }
        ).select('-password');

        res.json({
            message: 'Profilbillede opdateret',
            user
        });
    } catch (error) {
        console.error('Fejl ved upload af profilbillede:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

// Change password endpoint
app.post('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.session.userId);

        if (!user) {
            return res.status(404).json({ message: 'Bruger ikke fundet' });
        }

        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Nuværende adgangskode er forkert' });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.json({ message: 'Adgangskode ændret succesfuldt' });
    } catch (error) {
        console.error('Fejl ved ændring af adgangskode:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

// Admin middleware
const isAdmin = async (req, res, next) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: 'Ingen adgang' });
        }
        next();
    } catch (error) {
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
};

// Admin endpoints
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        console.error('Fejl ved hentning af brugere:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.put('/api/admin/users/:userId/block', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ message: 'Bruger ikke fundet' });
        }
        if (user.isAdmin) {
            return res.status(403).json({ message: 'Kan ikke blokere admin brugere' });
        }
        user.isBlocked = true;
        await user.save();
        res.json({ message: 'Bruger deaktiveret' });
    } catch (error) {
        console.error('Fejl ved blokering af bruger:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.put('/api/admin/users/:userId/unblock', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ message: 'Bruger ikke fundet' });
        }
        user.isBlocked = false;
        await user.save();
        res.json({ message: 'Bruger genaktiveret' });
    } catch (error) {
        console.error('Fejl ved genaktivering af bruger:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

// Category endpoints
app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const categories = await Category.find({ userId: req.session.userId })
            .sort('order');
        res.json(categories);
    } catch (error) {
        console.error('Fejl ved hentning af kategorier:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
    try {
        const category = new Category({
            ...req.body,
            userId: req.session.userId
        });
        await category.save();
        res.status(201).json(category);
    } catch (error) {
        console.error('Fejl ved oprettelse af kategori:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.put('/api/categories/:id', authenticateToken, async (req, res) => {
    try {
        const category = await Category.findOneAndUpdate(
            { _id: req.params.id, userId: req.session.userId },
            req.body,
            { new: true }
        );
        if (!category) {
            return res.status(404).json({ message: 'Kategori ikke fundet' });
        }
        res.json(category);
    } catch (error) {
        console.error('Fejl ved opdatering af kategori:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
    try {
        const category = await Category.findOneAndDelete({
            _id: req.params.id,
            userId: req.session.userId
        });
        if (!category) {
            return res.status(404).json({ message: 'Kategori ikke fundet' });
        }
        // Opdater alle stands i denne kategori til ingen kategori
        await Stand.updateMany(
            { categoryId: req.params.id },
            { $unset: { categoryId: "" } }
        );
        res.json({ message: 'Kategori slettet' });
    } catch (error) {
        console.error('Fejl ved sletning af kategori:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

// Reorder endpoints
app.post('/api/categories/reorder', authenticateToken, async (req, res) => {
    try {
        const { categories } = req.body;
        const updates = categories.map((cat, index) => ({
            updateOne: {
                filter: { _id: cat._id, userId: req.session.userId },
                update: { $set: { order: index } }
            }
        }));
        await Category.bulkWrite(updates);
        res.json({ message: 'Rækkefølge opdateret' });
    } catch (error) {
        console.error('Fejl ved omarrangering:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

app.post('/api/stands/reorder', authenticateToken, async (req, res) => {
    try {
        const { stands } = req.body;
        const updates = stands.map((stand, index) => ({
            updateOne: {
                filter: { _id: stand._id, userId: req.session.userId },
                update: { $set: { order: index } }
            }
        }));
        await Stand.bulkWrite(updates);
        res.json({ message: 'Rækkefølge opdateret' });
    } catch (error) {
        console.error('Fejl ved omarrangering:', error);
        res.status(500).json({ message: 'Der opstod en serverfejl' });
    }
});

// Serve redirect page
app.get('/:standerId', async (req, res) => {
    try {
        const stand = await Stand.findOne({ standerId: req.params.standerId });
        if (!stand) {
            return res.status(404).send('Produkt ikke fundet');
        }

        // Opdater antal kliks
        stand.clicks = (stand.clicks || 0) + 1;
        
        // Tilføj klik til historikken
        const clickData = {
            timestamp: new Date(),
            ip: req.ip
        };
        
        if (!stand.clickHistory) {
            stand.clickHistory = [];
        }
        stand.clickHistory.push(clickData);

        // Gem ændringerne før vi sender respons
        try {
            await stand.save();
            console.log('Klik registreret for stand:', {
                standerId: stand.standerId,
                newClickCount: stand.clicks,
                timestamp: clickData.timestamp,
                redirectUrl: stand.redirectUrl
            });
        } catch (saveError) {
            console.error('Fejl ved gemning af klik:', saveError);
        }

        // Sikr at redirectUrl har http:// eller https://
        let redirectUrl = stand.redirectUrl;
        if (!redirectUrl.startsWith('http://') && !redirectUrl.startsWith('https://')) {
            redirectUrl = 'https://' + redirectUrl;
        }

        // Redirect direkte
        res.redirect(redirectUrl);
    } catch (error) {
        console.error('Fejl ved redirect:', error);
        res.status(500).send('Der opstod en serverfejl');
    }
});

// Registrer klik på stand
app.post('/api/stands/:standId/click', async (req, res) => {
    try {
        const stand = await Stand.findById(req.params.standId);
        if (!stand) {
            return res.status(404).json({ message: 'Produkt ikke fundet' });
        }

        // Opdater antal kliks
        stand.clicks = (stand.clicks || 0) + 1;
        await stand.save();

        res.json({ message: 'Klik registreret', clicks: stand.clicks });
    } catch (error) {
        console.error('Fejl ved registrering af klik:', error);
        res.status(500).json({ error: 'Der opstod en fejl ved registrering af klik' });
    }
});

// Google Maps integration endpoints
app.get('/api/business/google-reviews', authenticateToken, googleBusinessLimiter, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user || !user.googlePlaceId) {
            return res.status(404).json({ 
                message: 'Ingen virksomhed tilknyttet',
                needsAuth: true
            });
        }

        // Tjek cache først
        const cacheKey = `business_${user.googlePlaceId}`;
        const cachedData = businessCache.get(cacheKey);
        if (cachedData) {
            console.log('Returnerer cached virksomhedsdata for:', user.googlePlaceId);
            return res.json(cachedData);
        }

        // Opret Google Maps klient
        const client = new Client({});

        // Hent detaljerede virksomhedsoplysninger
        const placeDetails = await client.placeDetails({
            params: {
                place_id: user.googlePlaceId,
                key: process.env.GOOGLE_MAPS_API_KEY,
                fields: [
                    'name',
                    'formatted_address',
                    'formatted_phone_number',
                    'website',
                    'rating',
                    'user_ratings_total',
                    'reviews'
                ]
            }
        });

        const responseData = {
            business: {
                name: placeDetails.data.result.name,
                formatted_address: placeDetails.data.result.formatted_address,
                formatted_phone_number: placeDetails.data.result.formatted_phone_number,
                website: placeDetails.data.result.website,
                rating: placeDetails.data.result.rating,
                user_ratings_total: placeDetails.data.result.user_ratings_total,
                place_id: user.googlePlaceId
            },
            reviews: placeDetails.data.result.reviews || []
        };

        // Gem i cache
        businessCache.set(cacheKey, responseData);

        res.json(responseData);

    } catch (error) {
        console.error('Fejl ved hentning af Google Maps data:', {
            error: error.message,
            stack: error.stack
        });
        
        if (error.response?.status === 401) {
            return res.status(401).json({
                message: 'Din Google Business autorisation er udløbet. Log venligst ind igen.',
                needsAuth: true
            });
        }

        res.status(500).json({ 
            message: 'Der opstod en fejl ved hentning af virksomhedsdata',
            error: error.message
        });
    }
});

app.post('/api/business/setup-google-maps', authenticateToken, async (req, res) => {
    try {
        const { placeId } = req.body;
        console.log('Modtaget anmodning om at opsætte Google Maps:', {
            userId: req.session.userId,
            placeId: placeId
        });

        if (!placeId) {
            return res.status(400).json({ message: 'Place ID er påkrævet' });
        }

        if (!process.env.GOOGLE_MAPS_API_KEY) {
            console.error('Google Maps API nøgle mangler i miljøvariablerne');
            return res.status(500).json({ message: 'Google Maps API nøgle er ikke konfigureret' });
        }

        // Verificer at Place ID er gyldigt
        const placeDetailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
        console.log('Kalder Google Places API for validering:', placeDetailsUrl);

        const placeDetailsResponse = await axios.get(placeDetailsUrl);
        console.log('Google Places API valideringssvar:', placeDetailsResponse.data);

        if (placeDetailsResponse.data.status === 'REQUEST_DENIED') {
            console.error('Google Places API afviste anmodningen:', placeDetailsResponse.data.error_message);
            return res.status(500).json({ message: 'Kunne ikke validere Place ID' });
        }

        if (!placeDetailsResponse.data.result) {
            return res.status(400).json({ message: 'Ugyldigt Place ID' });
        }

        // Opdater brugerens Google Place ID
        const user = await User.findByIdAndUpdate(
            req.session.userId,
            { googlePlaceId: placeId },
            { new: true }
        );

        console.log('Bruger opdateret med nyt Place ID:', {
            userId: user._id,
            placeId: user.googlePlaceId
        });

        const placeDetails = placeDetailsResponse.data.result;
        
        res.json({
            business: {
                name: placeDetails.name,
                rating: placeDetails.rating,
                user_ratings_total: placeDetails.user_ratings_total,
                place_id: placeId,
                formatted_address: placeDetails.formatted_address,
                formatted_phone_number: placeDetails.formatted_phone_number,
                website: placeDetails.website
            },
            reviews: placeDetails.reviews || []
        });
    } catch (error) {
        console.error('Detaljeret fejl ved opsætning af Google Maps:', {
            error: error.message,
            stack: error.stack,
            response: error.response?.data
        });
        res.status(500).json({ message: 'Der opstod en fejl ved opsætning af Google Maps' });
    }
});

// Opdater locations endpoint
app.get('/api/business/locations', authenticateToken, googleBusinessLimiter, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        console.log('Henter lokationer for bruger:', {
            userId: user._id,
            hasAccessToken: !!user.googleAccessToken,
            accessToken: user.googleAccessToken?.substring(0, 20) + '...',
            email: user.email
        });
        
        if (!user.googleAccessToken) {
            return res.status(401).json({ 
                message: 'Ingen Google Business Profile tilknyttet',
                needsAuth: true 
            });
        }

        // Tjek cache først med længere TTL
        const cacheKey = `locations_${user._id}`;
        const cachedLocations = businessCache.get(cacheKey);
        if (cachedLocations) {
            console.log('Returnerer cachede lokationer for bruger:', user._id);
            return res.json({ locations: cachedLocations });
        }

        // Tilføj retry delay funktion
        const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

        // Opdater fetchWithRetry funktionen
        const fetchWithRetry = async (retryCount = 0, maxRetries = 3) => {
            try {
                if (retryCount > 0) {
                    const delay = Math.min(Math.pow(2, retryCount) * 5000, 30000); // Start med længere delays
                    console.log(`Venter ${delay}ms før næste forsøg...`);
                    await wait(delay);
                }

                // Først henter vi OAuth2 token info for at verificere token
                const tokenInfoResponse = await axios.get(
                    `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${user.googleAccessToken}`
                );
                
                console.log('Token info response:', {
                    status: tokenInfoResponse.status,
                    scopes: tokenInfoResponse.data.scope
                });

                // Brug den nye version af Business Profile API
                const accountResponse = await axios.get(
                    'https://mybusinessbusinessinformation.googleapis.com/v1/accounts',
                    {
                        headers: {
                            'Authorization': `Bearer ${user.googleAccessToken}`,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        }
                    }
                );

                console.log('Google Business API svar (konti):', {
                    status: accountResponse.status,
                    hasAccounts: !!accountResponse.data.accounts,
                    accountCount: accountResponse.data.accounts?.length,
                    firstAccount: accountResponse.data.accounts?.[0]?.name
                });

                if (!accountResponse.data.accounts || accountResponse.data.accounts.length === 0) {
                    return res.status(404).json({ 
                        message: 'Ingen Google Business konti fundet',
                        needsAuth: true 
                    });
                }

                const accountName = accountResponse.data.accounts[0].name;
                
                // Tilføj kort delay mellem kald
                await new Promise(resolve => setTimeout(resolve, 1000));

                // Brug den nye version af API'en til at hente lokationer
                const locationsResponse = await axios.get(
                    `https://mybusinessbusinessinformation.googleapis.com/v1/${accountName}/locations`,
                    {
                        headers: {
                            'Authorization': `Bearer ${user.googleAccessToken}`,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        }
                    }
                );

                console.log('Google Business API svar (lokationer):', {
                    status: locationsResponse.status,
                    hasLocations: !!locationsResponse.data.locations,
                    locationCount: locationsResponse.data.locations?.length
                });

                const locations = (locationsResponse.data.locations || []).map(location => ({
                    placeId: location.placeId || location.name,
                    name: location.locationName || location.title || location.name,
                    address: location.address?.formattedAddress || location.address?.locality || 'Ingen adresse'
                }));

                // Gem i cache med længere TTL ved succes
                if (locations.length > 0) {
                    businessCache.set(cacheKey, locations, 600); // 10 minutter
                    console.log('Lokationer gemt i cache:', locations.length);
                }

                return locations;
            } catch (error) {
                console.error('API fejl detaljer:', {
                    status: error.response?.status,
                    statusText: error.response?.statusText,
                    data: error.response?.data,
                    message: error.message,
                    config: {
                        url: error.config?.url,
                        headers: error.config?.headers
                    }
                });

                if (error.response?.status === 401) {
                    // Token er udløbet eller ugyldig
                    return res.status(401).json({
                        message: 'Din Google Business autorisation er udløbet. Log venligst ind igen.',
                        needsAuth: true
                    });
                }

                if (error.response?.status === 403) {
                    // Manglende tilladelser
                    return res.status(403).json({
                        message: 'Du har ikke de nødvendige tilladelser. Prøv at logge ind igen med de korrekte tilladelser.',
                        needsAuth: true
                    });
                }

                if (error.response?.status === 429 && retryCount < maxRetries) {
                    const retryAfter = parseInt(error.response.headers['retry-after']) || 
                        Math.pow(2, retryCount + 1) * 5000;
                    
                    console.log(`Rate limit nået. Venter ${retryAfter}ms før næste forsøg...`);
                    await wait(retryAfter);
                    return fetchWithRetry(retryCount + 1, maxRetries);
                }

                throw error;
            }
        };

        const locations = await fetchWithRetry();
        res.json({ locations });

    } catch (error) {
        console.error('Detaljeret fejl ved hentning af lokationer:', {
            error: error.message,
            response: error.response?.data,
            stack: error.stack
        });
        
        if (error.response?.status === 429) {
            const retryAfter = parseInt(error.response.headers['retry-after']) || 60;
            return res.status(429).json({ 
                message: `For mange forsøg. Prøv igen om ${retryAfter} sekunder.`,
                needsAuth: false,
                retryAfter
            });
        }
        
        if (error.response?.status === 401 || error.response?.status === 403) {
            return res.status(401).json({ 
                message: 'Google autorisation udløbet eller ugyldig. Prøv at logge ind igen.',
                needsAuth: true 
            });
        }
        
        res.status(500).json({ 
            message: 'Der opstod en fejl ved hentning af lokationer. Prøv igen senere.',
            needsAuth: true,
            error: error.message
        });
    }
});

// Nyt endpoint til at logge ud af Google Business
app.post('/api/business/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Nulstil Google Business relaterede felter
    user.googlePlaceId = null;
    user.googleAccessToken = null;
    user.googleRefreshToken = null;
    await user.save();

    res.json({ message: 'Logget ud af Google Business Profile' });
  } catch (error) {
    console.error('Fejl ved logout af Google Business:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved logout' });
  }
});

// Tilføj endpoint til at forberede business auth
app.post('/api/auth/prepare-business-auth', authenticateToken, (req, res) => {
    try {
        // Gem den originale session ID
        req.session.originalSessionID = req.sessionID;
        
        // Gem explicit
        req.session.save((err) => {
            if (err) {
                console.error('Fejl ved gemning af original session:', err);
                return res.status(500).json({ message: 'Kunne ikke gemme session' });
            }
            res.json({ message: 'Session gemt' });
        });
    } catch (error) {
        console.error('Fejl ved forberedelse af auth:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved forberedelse af autorisation' });
    }
});

// Nyt endpoint til at søge efter virksomheder
app.get('/api/business/search', authenticateToken, placesSearchLimiter, async (req, res) => {
    try {
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

        // Implementer exponential backoff
        const fetchWithRetry = async (retryCount = 0) => {
            try {
                if (retryCount > 0) {
                    const delay = Math.min(Math.pow(2, retryCount) * 1000, 10000);
                    console.log(`Venter ${delay}ms før næste forsøg...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }

                const searchUrl = `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(searchQuery)}&key=${process.env.GOOGLE_MAPS_API_KEY}&language=da&region=dk&type=establishment`;
                const searchResponse = await axios.get(searchUrl);

                if (searchResponse.data.status === 'ZERO_RESULTS') {
                    return [];
                }

                if (searchResponse.data.status === 'REQUEST_DENIED') {
                    throw new Error(searchResponse.data.error_message || 'API anmodning afvist');
                }

                if (searchResponse.data.status === 'OVER_QUERY_LIMIT') {
                    if (retryCount < 3) {
                        return await fetchWithRetry(retryCount + 1);
                    }
                    throw new Error('API kvote overskredet');
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
                return places;
            } catch (error) {
                if (error.response?.status === 429 && retryCount < 3) {
                    return await fetchWithRetry(retryCount + 1);
                }
                throw error;
            }
        };

        const places = await fetchWithRetry();
        res.json({ places });

    } catch (error) {
        console.error('Fejl ved søgning efter virksomheder:', {
            error: error.message,
            response: error.response?.data,
            stack: error.stack
        });

        if (error.response?.status === 429) {
            return res.status(429).json({ 
                message: 'For mange anmodninger. Prøv igen om et øjeblik.',
                retryAfter: 60
            });
        }

        res.status(500).json({ 
            message: 'Der opstod en fejl ved søgning. Prøv igen senere.',
            error: error.message
        });
    }
});

// Konfigurer app indstillinger
app.set('trust proxy', 1);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server fejl:', err);
    res.status(500).json({
        message: 'Der opstod en serverfejl',
        error: process.env.NODE_ENV === 'production' ? {} : err.message
    });
});

// 404 handler skal være sidste middleware
app.use((req, res) => {
    console.log('404 Fejl:', {
        method: req.method,
        url: req.url,
        path: req.path,
        headers: req.headers,
        body: req.body,
        timestamp: new Date().toISOString()
    });
    res.status(404).json({ message: 'Endpoint ikke fundet' });
});

// Landing Pages endpoints
app.post('/api/landing-pages', authenticateToken, upload.fields([
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

app.get('/api/landing-pages', authenticateToken, async (req, res) => {
  try {
    const pages = await LandingPage.find({ userId: req.session.userId });
    res.json(pages);
  } catch (error) {
    console.error('Fejl ved hentning af landing pages:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing pages' });
  }
});

app.put('/api/landing-pages/:id', authenticateToken, upload.fields([
  { name: 'logo', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description, backgroundColor, buttonColor, buttonTextColor, titleColor, buttons, showTitle, socialLinks } = req.body;
    const updates = {
      title,
      description,
      backgroundColor,
      buttonColor,
      buttonTextColor,
      titleColor,
      buttons: JSON.parse(buttons || '[]'),
      showTitle: showTitle === 'true',
      socialLinks: JSON.parse(socialLinks || '{}')
    };

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
      updates.logo = logoResult.secure_url;
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
      updates.backgroundImage = backgroundResult.secure_url;
    }

    const page = await LandingPage.findOneAndUpdate(
      { _id: req.params.id, userId: req.session.userId },
      updates,
      { new: true }
    );

    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }

    res.json(page);
  } catch (error) {
    console.error('Fejl ved opdatering af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved opdatering af landing page' });
  }
});

app.delete('/api/landing-pages/:id', authenticateToken, async (req, res) => {
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
app.get('/api/landing/:id', async (req, res) => {
  try {
    const page = await LandingPage.findById(req.params.id);
    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }
    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

module.exports = app;
