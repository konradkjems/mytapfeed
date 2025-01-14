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
const { google } = require('googleapis');
const path = require('path');
const { Client } = require('@googlemaps/google-maps-services-js');
const LandingPage = require('./models/LandingPage');
const landingPagesRouter = require('./routes/landingPages');
const userRouter = require('./routes/user');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const QRCode = require('qrcode');
const adminRouter = require('./routes/admin');
const { requireAuth, isAdmin } = require('./middleware/auth');

// Cache konfiguration
const businessCache = new NodeCache({ 
    stdTTL: 1800,  // Øg til 30 minutter (fra 10 minutter)
    checkperiod: 300,  // Tjek for udløbne keys hvert 5. minut
    deleteOnExpire: false  // Behold udløbne værdier indtil nye er hentet
});

// Rate limiter konfiguration
const googleBusinessLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minut
    max: 2, // Reducer til max 2 requests per minut
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

// CORS konfiguration først
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.NODE_ENV === 'production'
      ? [
          'https://my.tapfeed.dk',
          'https://api.tapfeed.dk',
          'https://tapfeed.dk',
          /^https:\/\/.*\.tapfeed\.dk$/
        ]
      : ['http://localhost:3001', 'http://localhost:3000'];

    if (!origin || allowedOrigins.some(allowed => 
      allowed instanceof RegExp ? allowed.test(origin) : allowed === origin
    )) {
      callback(null, true);
    } else {
      callback(new Error('CORS ikke tilladt'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['set-cookie'],
  preflightContinue: false,
  optionsSuccessStatus: 204
};

// Anvend CORS før alle andre middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session konfiguration
app.use(session({
    secret: process.env.SESSION_SECRET || 'mytapfeed-dev-secret-key',
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
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        domain: process.env.NODE_ENV === 'production' ? '.tapfeed.dk' : 'localhost'
    },
    proxy: true
}));

// Initialize Passport
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

// Tilføj ekstra debug logging for session problemer
app.use((req, res, next) => {
    if (!req.session) {
        console.error('Session ikke tilgængelig:', {
            headers: req.headers,
            cookies: req.cookies
        });
    }
    next();
});

// Registrer routes
app.use('/api/admin', adminRouter);
app.use('/api/landing-pages', landingPagesRouter);
app.use('/api/user', userRouter);

// Basic routes
app.get('/', (req, res) => {
    res.json({ message: 'Velkommen til TapFeed API' });
});

app.get('/api', (req, res) => {
    res.json({ message: 'TapFeed API er kørende' });
});

// Auth routes
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

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ message: 'Ikke autoriseret' });
        }

        // Hent brugerdata og sæt det på request objektet
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(401).json({ message: 'Bruger ikke fundet' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved autorisation' });
    }
};

// Hent alle unclaimed stands (før det generelle endpoint)
app.get('/api/stands/unclaimed', authenticateToken, async (req, res) => {
    try {
        // Tjek om brugeren er admin
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Kun administratorer kan se unclaimed produkter' });
        }

        const stands = await Stand.find({ status: 'unclaimed' })
            .sort({ createdAt: -1 });

        console.log('Hentede unclaimed stands:', {
            count: stands.length,
            stands: stands.map(s => ({
                id: s._id,
                standerId: s.standerId,
                status: s.status,
                createdAt: s.createdAt
            }))
        });

        res.json(stands);
    } catch (error) {
        console.error('Fejl ved hentning af unclaimed stands:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved hentning af unclaimed produkter' });
    }
});

// Offentligt endpoint til at hente et enkelt produkt baseret på standerId
app.get('/api/stands/:standerId', async (req, res) => {
  try {
    console.log('Henter stand med ID:', req.params.standerId);
    const stand = await Stand.findOne({ standerId: req.params.standerId });
    
    if (!stand) {
      console.log('Stand ikke fundet');
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    console.log('Stand fundet:', {
      id: stand._id,
      standerId: stand.standerId,
      claimed: stand.claimed,
      configured: stand.configured
    });

    const publicStand = {
      _id: stand._id,
      standerId: stand.standerId,
      status: stand.status,
      redirectUrl: stand.redirectUrl,
      landingPageId: stand.landingPageId,
      claimed: stand.claimed,
      configured: stand.configured,
      type: stand.type,
      name: stand.name
    };

    res.json(publicStand);
  } catch (error) {
    console.error('Fejl ved hentning af produkt:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af produkt' });
  }
});

// Beskyttede routes
app.use('/api/stands', authenticateToken);

app.get('/api/auth/status', (req, res) => {
    console.log('Auth status check:', {
        sessionID: req.sessionID,
        session: req.session,
        user: req.user,
        isAuthenticated: req.isAuthenticated()
    });

    res.json({
        isAuthenticated: req.isAuthenticated(),
        user: req.user ? {
            id: req.user._id,
            username: req.user.username,
            email: req.user.email
        } : null
    });
});

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
        : "http://localhost:3001/api/auth/google/callback",
    proxy: true
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
                googleId: profile.id,
                googleAccessToken: accessToken,
                googleRefreshToken: refreshToken
            });
            await user.save();
            console.log('New user created:', user._id);
        } else {
            // Update tokens
            user.googleAccessToken = accessToken;
            user.googleRefreshToken = refreshToken;
            await user.save();
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
    passport.authenticate('google', { 
        failureRedirect: process.env.NODE_ENV === 'production' 
            ? 'https://my.tapfeed.dk/login'
            : 'http://localhost:3001/login',
        failureMessage: true
    }),
    function(req, res) {
        // Log detaljeret session og bruger info
        console.log('Google OAuth callback detaljer:', {
            sessionID: req.sessionID,
            user: req.user,
            session: req.session,
            isAuthenticated: req.isAuthenticated(),
            headers: req.headers
        });

        // Gem bruger ID i session
        req.session.userId = req.user._id;
        
        // Gem session før redirect
        req.session.save((err) => {
            if (err) {
                console.error('Fejl ved gem af session:', err);
                return res.redirect(process.env.NODE_ENV === 'production'
                    ? 'https://my.tapfeed.dk/login?error=session'
                    : 'http://localhost:3001/login?error=session'
                );
            }

            // Double-check session efter gem
            console.log('Session efter gem:', {
                sessionID: req.sessionID,
                session: req.session,
                userId: req.session.userId
            });

            // Redirect til frontend med session ID
            const frontendUrl = process.env.NODE_ENV === 'production'
                ? 'https://my.tapfeed.dk'
                : 'http://localhost:3001';
            
            const redirectUrl = `${frontendUrl}/login?sessionId=${req.sessionID}`;
            console.log('Redirecter til:', redirectUrl);
            res.redirect(redirectUrl);
        });
    }
);

// Google Business auth endpoints
app.get('/api/auth/google-business', (req, res) => {
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.NODE_ENV === 'production'
      ? "https://api.tapfeed.dk/api/auth/google-business/callback"
      : "http://localhost:3000/api/auth/google-business/callback"
  );

  const scopes = [
    'https://www.googleapis.com/auth/business.manage',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email'
  ];

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent'
  });

  res.redirect(authUrl);
});

app.get('/api/auth/google-business/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.NODE_ENV === 'production'
        ? "https://api.tapfeed.dk/api/auth/google-business/callback"
        : "http://localhost:3000/api/auth/google-business/callback"
    );

    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Gem tokens i brugerens session
    const user = await User.findById(req.session.userId);
    if (!user) {
      const frontendUrl = process.env.NODE_ENV === 'production'
        ? 'https://my.tapfeed.dk'
        : 'http://localhost:3001';
      return res.redirect(`${frontendUrl}/settings?error=user-not-found`);
    }

    user.googleAccessToken = tokens.access_token;
    user.googleRefreshToken = tokens.refresh_token;
    await user.save();

    // Redirect tilbage til settings siden
    const frontendUrl = process.env.NODE_ENV === 'production'
      ? 'https://my.tapfeed.dk'
      : 'http://localhost:3001';
    res.redirect(`${frontendUrl}/settings?success=true`);
  } catch (error) {
    console.error('Fejl ved Google Business callback:', error);
    const frontendUrl = process.env.NODE_ENV === 'production'
      ? 'https://my.tapfeed.dk'
      : 'http://localhost:3001';
    res.redirect(`${frontendUrl}/settings?error=auth-failed`);
  }
});

// Google Business logout endpoint
app.post('/api/auth/google-business/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Nulstil Google tokens
    user.googlePlaceId = null;
    user.googleAccessToken = null;
    user.googleRefreshToken = null;
    await user.save();

    // Ryd cache for brugerens anmeldelser
    if (user.googlePlaceId) {
      const cacheKey = `reviews_${user.googlePlaceId}`;
      businessCache.del(cacheKey);
    }

    res.json({ message: 'Logget ud af Google Business Profile' });
  } catch (error) {
    console.error('Fejl ved logout af Google Business:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved logout' });
  }
});

// Auth endpoints
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
// Hent alle unclaimed stands
app.get('/api/stands/unclaimed', authenticateToken, async (req, res) => {
    try {
        // Tjek om brugeren er admin
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Kun administratorer kan se unclaimed produkter' });
        }

        const stands = await Stand.find({ status: 'unclaimed' })
            .sort({ createdAt: -1 });

        console.log('Hentede unclaimed stands:', {
            count: stands.length,
            stands: stands.map(s => ({
                id: s._id,
                standerId: s.standerId,
                status: s.status,
                createdAt: s.createdAt
            }))
        });

        res.json(stands);
    } catch (error) {
        console.error('Fejl ved hentning af unclaimed stands:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved hentning af unclaimed produkter' });
    }
});

// Download CSV af unclaimed stands
app.get('/api/stands/unclaimed/csv', requireAuth, async (req, res) => {
    try {
        // Tjek om brugeren er admin
        const user = await User.findById(req.session.userId);
        if (!user?.isAdmin) {
            return res.status(403).json({ message: 'Kun administratorer kan downloade produkt liste' });
        }

        // Hent valgte produkter hvis ids er angivet, ellers alle unclaimed
        const query = { status: 'unclaimed' };
        if (req.query.ids) {
            const ids = req.query.ids.split(',');
            query._id = { $in: ids };
        }

        const stands = await Stand.find(query)
            .sort({ createdAt: -1 });

        // Generer CSV indhold
        const csvRows = ['Produkt ID,Produkttype,TapFeed URL,Oprettet'];
        stands.forEach(stand => {
            const tapfeedUrl = `https://api.tapfeed.dk/${stand.standerId}`;
            csvRows.push(`${stand.standerId},${stand.productType},${tapfeedUrl},${new Date(stand.createdAt).toLocaleString('da-DK')}`);
        });
        const csvContent = csvRows.join('\n');

        // Send CSV fil
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=unclaimed-produkter.csv');
        res.send(csvContent);
    } catch (error) {
        console.error('Fejl ved generering af CSV:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved generering af CSV fil' });
    }
});

// Download QR koder som ZIP
app.get('/api/stands/unclaimed/qr-codes', authenticateToken, async (req, res) => {
    try {
        // Tjek om brugeren er admin
        const user = await User.findById(req.session.userId);
        if (!user?.isAdmin) {
            return res.status(403).json({ message: 'Kun administratorer kan downloade QR koder' });
        }

        // Hent valgte produkter hvis ids er angivet, ellers alle unclaimed
        const query = { status: 'unclaimed' };
        if (req.query.ids) {
            const ids = req.query.ids.split(',');
            query._id = { $in: ids };
        }

        const stands = await Stand.find(query)
            .sort({ createdAt: -1 });

        // Opret en ny ZIP fil
        const AdmZip = require('adm-zip');
        const zip = new AdmZip();

        // Generer QR koder for hver stand og tilføj til ZIP
        await Promise.all(stands.map(async stand => {
            const tapfeedUrl = `https://api.tapfeed.dk/${stand.standerId}`;
            
            // Generer QR kode som PNG buffer
            const qrBuffer = await QRCode.toBuffer(tapfeedUrl, {
                errorCorrectionLevel: 'H',
                type: 'png',
                margin: 1,
                width: 1000,
                color: {
                    dark: '#000000',
                    light: '#ffffff'
                }
            });

            // Tilføj QR kode til ZIP filen
            zip.addFile(`QR Koder/${stand.standerId}.png`, qrBuffer);
        }));

        // Generer ZIP filen
        const zipBuffer = zip.toBuffer();

        // Send ZIP fil
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename=tapfeed-qr-koder.zip');
        res.send(zipBuffer);
    } catch (error) {
        console.error('Fejl ved generering af QR koder:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved generering af QR koder' });
    }
});

// Hent alle stands for en bruger
app.get('/api/stands', requireAuth, async (req, res) => {
    try {
        const stands = await Stand.find({ 
            $or: [
                { ownerId: req.session.userId },
                { userId: req.session.userId }
            ]
        }).populate('landingPageId');
        res.json(stands);
    } catch (error) {
        console.error('Fejl ved hentning af stands:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved hentning af stands' });
    }
});

// Opret ny stand
app.post('/api/stands', requireAuth, async (req, res) => {
    try {
        const { standerId, redirectUrl, productType, nickname, status } = req.body;

        // Tjek om standerID allerede eksisterer
        const existingStand = await Stand.findOne({ standerId });
        if (existingStand) {
            return res.status(409).json({ message: 'Stander ID eksisterer allerede' });
        }

        const stand = new Stand({
            standerId,
            redirectUrl,
            productType,
            nickname,
            status: status || 'claimed',
            ownerId: req.session.userId,
            userId: req.session.userId  // For bagudkompatibilitet
        });

        await stand.save();
        res.status(201).json(stand);
    } catch (error) {
        console.error('Fejl ved oprettelse af stand:', error);
        res.status(500).json({ message: 'Der opstod en fejl ved oprettelse af stand' });
    }
});

// Bulk opret stands
app.post('/api/stands/bulk', requireAuth, async (req, res) => {
    try {
        const { products } = req.body;

        // Tjek om brugeren er admin
        const user = await User.findById(req.session.userId);
        if (!user?.isAdmin) {
            return res.status(403).json({ message: 'Kun administratorer kan oprette bulk produkter' });
        }

        // Tjek om nogle af produkt ID'erne allerede eksisterer
        const existingStands = await Stand.find({
            standerId: { $in: products.map(p => p.standerId) }
        });

        if (existingStands.length > 0) {
            return res.status(409).json({
                message: 'Nogle produkt ID\'er eksisterer allerede',
                existingIds: existingStands.map(s => s.standerId)
            });
        }

        // Tilføj configured: false til alle produkter
        const productsWithConfig = products.map(product => ({
            ...product,
            status: 'unclaimed',
            configured: false
        }));

        // Opret alle produkter
        const createdStands = await Stand.insertMany(productsWithConfig);

        res.status(201).json({
            message: `${createdStands.length} produkter oprettet succesfuldt`,
            stands: createdStands
        });
    } catch (error) {
        console.error('Fejl ved bulk oprettelse af produkter:', error);
        res.status(500).json({
            message: 'Der opstod en fejl ved oprettelse af produkterne',
            error: error.message
        });
    }
});

// Opdater stand
app.put('/api/stands/:id', authenticateToken, async (req, res) => {
  try {
    const { nickname, landingPageId, redirectUrl } = req.body;
    
    // Tjek om landing page eksisterer og tilhører brugeren
    if (landingPageId) {
      const landingPage = await LandingPage.findOne({
        _id: landingPageId,
        userId: req.session.userId
      });
      
      if (!landingPage) {
        return res.status(404).json({ message: 'Landing page ikke fundet' });
      }
    }

    // Et produkt er konfigureret hvis det har enten en redirectUrl eller en landingPageId
    const configured = !!(redirectUrl || landingPageId);

    const stand = await Stand.findOneAndUpdate(
      { 
        _id: req.params.id,
        $or: [
          { userId: req.session.userId },
          { ownerId: req.session.userId }
        ]
      },
      { 
        $set: {
          nickname: nickname || null,
          landingPageId: landingPageId || null,
          redirectUrl: redirectUrl || null,
          configured
        }
      },
      { new: true }
    );

    if (!stand) {
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    console.log('Produkt opdateret:', {
      id: stand._id,
      nickname,
      redirectUrl,
      landingPageId,
      configured
    });

    res.json(stand);
  } catch (error) {
    console.error('Fejl ved opdatering af produkt:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved opdatering af produktet' });
  }
});

app.delete('/api/stands/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await Stand.deleteOne({ 
            _id: id, 
            $or: [
                { ownerId: req.session.userId },
                { userId: req.session.userId }
            ]
        });
        
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

        console.log('Modtaget fil:', {
            originalname: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size
        });

        // Upload til Cloudinary med stream
        const result = await new Promise((resolve, reject) => {
            const uploadOptions = {
                folder: 'profile-images',
                transformation: [
                    { width: 300, height: 300, crop: 'fill' }
                ],
                resource_type: 'auto',
                format: 'jpg'
            };

            const uploadStream = cloudinary.uploader.upload_stream(
                uploadOptions,
                (error, result) => {
                    if (error) {
                        console.error('Cloudinary upload fejl:', error);
                        reject(error);
                        return;
                    }
                    console.log('Cloudinary upload success:', result);
                    resolve(result);
                }
            );

            // Konverter buffer til stream og pipe til Cloudinary
            const bufferStream = require('stream').Readable.from(req.file.buffer);
            bufferStream.pipe(uploadStream);
        });

        console.log('Cloudinary upload resultat:', {
            secure_url: result.secure_url,
            public_id: result.public_id,
            format: result.format,
            version: result.version
        });

        // Opdater bruger med nyt billede URL
        const user = await User.findByIdAndUpdate(
            req.session.userId,
            { profileImage: result.secure_url },
            { new: true }
        ).select('-password');

        console.log('Opdateret bruger:', {
            id: user._id,
            profileImage: user.profileImage
        });

        res.json({
            message: 'Profilbillede opdateret',
            user
        });
    } catch (error) {
        console.error('Detaljeret fejl ved upload af profilbillede:', {
            error: error.message,
            stack: error.stack
        });
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

// Admin endpoints
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    console.error('Fejl ved hentning af brugere:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af brugere' });
  }
});

// Slet unclaimed produkter
app.delete('/api/admin/stands/unclaimed', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const { ids } = req.body;
    let query = { status: 'unclaimed' };
    
    // Hvis specifikke IDs er angivet, slet kun disse
    if (ids && Array.isArray(ids) && ids.length > 0) {
      query._id = { $in: ids };
    }

    const result = await Stand.deleteMany(query);
    
    res.json({ 
      message: `${result.deletedCount} unclaimed produkter blev slettet`,
      deletedCount: result.deletedCount 
    });
  } catch (error) {
    console.error('Fejl ved sletning af unclaimed produkter:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved sletning af unclaimed produkter' });
  }
});

// Opdater bruger
app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const { username, email, isAdmin } = req.body;
    const userId = req.params.id;

    // Tjek om brugeren findes
    const userToUpdate = await User.findById(userId);
    if (!userToUpdate) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Opdater bruger
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, email, isAdmin },
      { new: true, select: '-password' }
    );

    res.json(updatedUser);
  } catch (error) {
    console.error('Fejl ved opdatering af bruger:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved opdatering af bruger' });
  }
});

// Nulstil adgangskode (Admin)
app.post('/api/admin/users/:id/reset-password', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const userId = req.params.id;
    const userToReset = await User.findById(userId);
    if (!userToReset) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Generer reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 time

    // Gem token i brugerens dokument
    await User.findByIdAndUpdate(userId, {
      resetPasswordToken: resetToken,
      resetPasswordExpires: resetTokenExpiry
    });

    // Generer reset URL
    const resetUrl = process.env.NODE_ENV === 'production'
      ? `https://my.tapfeed.dk/reset-password/${resetToken}`
      : `http://localhost:3001/reset-password/${resetToken}`;

    // Send email med reset link
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
      }
    });

    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: userToReset.email,
      subject: 'Nulstil din adgangskode - TapFeed',
      html: `
        <p>Hej ${userToReset.username},</p>
        <p>Din adgangskode er blevet nulstillet af en administrator.</p>
        <p>Klik på linket herunder for at vælge en ny adgangskode:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>Dette link udløber om 1 time.</p>
        <p>Hvis du ikke har anmodet om denne nulstilling, bedes du kontakte support.</p>
        <p>Venlig hilsen,<br>TapFeed Team</p>
      `
    });

    res.json({ message: 'Nulstillingslink sendt til brugerens email' });
  } catch (error) {
    console.error('Fejl ved nulstilling af adgangskode:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved nulstilling af adgangskode' });
  }
});

// Slet bruger
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    const adminUser = await User.findById(req.session.userId);
    if (!adminUser || !adminUser.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const userId = req.params.id;
    const userToDelete = await User.findById(userId);

    if (!userToDelete) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Tjek om brugeren der skal slettes er admin
    if (userToDelete.isAdmin) {
      return res.status(403).json({ message: 'Kan ikke slette admin brugere' });
    }

    // Slet brugerens landing pages
    await LandingPage.deleteMany({ userId: userId });

    // Slet brugeren
    await User.findByIdAndDelete(userId);

    res.json({ message: 'Bruger og tilhørende data slettet succesfuldt' });
  } catch (error) {
    console.error('Fejl ved sletning af bruger:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved sletning af bruger' });
  }
});

// Hent brugerens landing pages
app.get('/api/admin/users/:id/landing-pages', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    const adminUser = await User.findById(req.session.userId);
    if (!adminUser || !adminUser.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const userId = req.params.id;
    const userExists = await User.findById(userId);
    if (!userExists) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    const landingPages = await LandingPage.find({ userId: userId });
    res.json(landingPages);
  } catch (error) {
    console.error('Fejl ved hentning af brugerens landing pages:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing pages' });
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

// API endpoints skal være FØR catch-all routen
// Endpoint til at tjekke status for et produkt
app.get('/api/stands/check/:standerId', async (req, res) => {
  try {
    const stand = await Stand.findOne({ standerId: req.params.standerId });
    
    if (!stand) {
      return res.status(404).json({ 
        message: 'Produkt ikke fundet',
        status: 'not_found'
      });
    }

    const status = {
      standerId: stand.standerId,
      status: stand.status || (stand.claimed ? 'claimed' : 'unclaimed'),
      configured: stand.configured,
      hasRedirect: !!stand.redirectUrl,
      hasLandingPage: !!stand.landingPageId
    };

    console.log('Stand status tjek:', status);
    res.json(status);
  } catch (error) {
    console.error('Fejl ved tjek af produkt status:', error);
    res.status(500).json({ 
      message: 'Der opstod en fejl ved tjek af produkt status',
      status: 'error'
    });
  }
});

// Endpoint til at hente detaljer om et unclaimed produkt
app.get('/api/stands/unclaimed/:standerId', async (req, res) => {
  try {
    const stand = await Stand.findOne({ 
      standerId: req.params.standerId,
      status: 'unclaimed' // Kun tjek for explicit unclaimed status
    });

    if (!stand) {
      return res.status(404).json({ 
        message: 'Unclaimed produkt ikke fundet' 
      });
    }

    res.json({
      standerId: stand.standerId,
      productType: stand.productType,
      createdAt: stand.createdAt
    });
  } catch (error) {
    console.error('Fejl ved hentning af unclaimed produkt:', error);
    res.status(500).json({ 
      message: 'Der opstod en fejl ved hentning af unclaimed produkt' 
    });
  }
});

// Catch-all route skal være EFTER alle API endpoints
app.get('/:urlPath', async (req, res, next) => {
  try {
    // Ignorer requests til /api paths
    if (req.params.urlPath.startsWith('api/')) {
      return next();
    }

    console.log('Håndterer URL path i production:', {
      path: req.params.urlPath,
      environment: process.env.NODE_ENV,
      host: req.get('host'),
      referer: req.get('referer')
    });
    
    const stand = await Stand.findOne({ standerId: req.params.urlPath });
    console.log('Fundet stand:', stand ? {
      id: stand._id,
      standerId: stand.standerId,
      status: stand.status,
      configured: stand.configured,
      redirectUrl: stand.redirectUrl
    } : 'Ingen stand fundet');

    if (stand) {
      const frontendUrl = process.env.NODE_ENV === 'production'
        ? 'https://my.tapfeed.dk'
        : 'http://localhost:3001';

      // Tjek status og konfiguration
      if (stand.status === 'unclaimed') {
        const unclaimedUrl = `${frontendUrl}/unclaimed/${stand.standerId}`;
        console.log('Redirecter til unclaimed:', {
          url: unclaimedUrl,
          standStatus: stand.status,
          environment: process.env.NODE_ENV
        });
        return res.redirect(302, unclaimedUrl);
      } 
      
      if (!stand.configured || (!stand.redirectUrl && !stand.landingPageId)) {
        const notConfiguredUrl = `${frontendUrl}/not-configured/${stand.standerId}`;
        console.log('Redirecter til not-configured:', {
          url: notConfiguredUrl,
          standStatus: stand.status,
          configured: stand.configured,
          environment: process.env.NODE_ENV
        });
        return res.redirect(302, notConfiguredUrl);
      }
      
      if (stand.redirectUrl) {
        let redirectUrl = stand.redirectUrl;
        if (!redirectUrl.startsWith('http://') && !redirectUrl.startsWith('https://')) {
          redirectUrl = 'https://' + redirectUrl;
        }
        console.log('Redirecter til ekstern URL:', {
          url: redirectUrl,
          standStatus: stand.status,
          environment: process.env.NODE_ENV
        });
        stand.clicks = (stand.clicks || 0) + 1;
        await stand.save();
        return res.redirect(302, redirectUrl);
      }
    }

    const landingPage = await LandingPage.findOne({ urlPath: req.params.urlPath });
    if (landingPage) {
      const frontendUrl = process.env.NODE_ENV === 'production'
        ? 'https://my.tapfeed.dk'
        : 'http://localhost:3001';
      const landingPageUrl = `${frontendUrl}/landing/${landingPage._id}`;
      console.log('Redirecter til landing page:', {
        url: landingPageUrl,
        environment: process.env.NODE_ENV
      });
      return res.redirect(302, landingPageUrl);
    }

    console.log('Ingen match fundet - sender 404:', {
      path: req.params.urlPath,
      environment: process.env.NODE_ENV
    });
    res.status(404).send('Side ikke fundet');
  } catch (error) {
    console.error('Fejl ved håndtering af URL path:', {
      error: error.message,
      stack: error.stack,
      path: req.params.urlPath,
      environment: process.env.NODE_ENV
    });
    next(error);
  }
});

// Tilføj en catch-all route for frontend routes i production
app.get('*', (req, res) => {
  console.log('Håndterer frontend route:', {
    path: req.path,
    environment: process.env.NODE_ENV
  });
  
  // I production, send index.html for alle ukendte routes
  if (process.env.NODE_ENV === 'production') {
    res.sendFile(path.join(__dirname, 'frontend/build', 'index.html'));
  } else {
    res.status(404).send('Route ikke fundet');
  }
});

// Endpoint til at claime et produkt
app.post('/api/stands/:standerId/claim', authenticateToken, async (req, res) => {
    try {
        console.log('Forsøger at claime produkt:', {
            standerId: req.params.standerId,
            userId: req.user._id
        });

        // Find produktet og tjek at det er unclaimed
        const stand = await Stand.findOne({ 
            standerId: req.params.standerId,
            status: 'unclaimed'
        });

        if (!stand) {
            console.log('Produkt ikke fundet eller allerede claimed:', req.params.standerId);
            return res.status(404).json({ 
                message: 'Produkt ikke fundet eller er allerede aktiveret' 
            });
        }

        // Opdater stand med den nye ejer
        stand.status = 'claimed';
        stand.ownerId = req.user._id;
        stand.claimedAt = new Date();
        stand.configured = false; // Sæt configured til false når produktet først bliver claimed
        await stand.save();

        console.log('Produkt claimed succesfuldt:', {
            standerId: stand.standerId,
            userId: req.user._id,
            status: stand.status
        });

        // Send succes respons
        res.json({ 
            message: 'Produkt aktiveret succesfuldt',
            stand 
        });
    } catch (error) {
        console.error('Fejl ved aktivering af produkt:', error);
        res.status(500).json({ 
            message: 'Der opstod en fejl ved aktivering af produktet' 
        });
    }
});

// Registrer klik på stand
app.post('/api/stands/:standId/click', async (req, res) => {
    try {
        const stand = await Stand.findById(req.params.standId);
        if (!stand) {
            return res.status(404).json({ message: 'Produkt ikke fundet' });
        }

        // Opdater antal kliks og clickHistory
        stand.clicks = (stand.clicks || 0) + 1;
        const now = new Date();
        stand.clickHistory.push({ timestamp: now });
        
        await stand.save();

        console.log('Klik registreret:', {
            standId: stand._id,
            clicks: stand.clicks,
            clickTime: now.toISOString()
        });

        res.json({ message: 'Klik registreret', clicks: stand.clicks });
    } catch (error) {
        console.error('Fejl ved registrering af klik:', error);
        res.status(500).json({ error: 'Der opstod en fejl ved registrering af klik' });
    }
});

// Rate limiters
const googleReviewsLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minut
    max: 2, // max 2 requests per vindue
    message: { message: 'For mange forsøg. Prøv igen senere.' }
});

const landingPagesLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minut
    max: 10, // max 10 requests per vindue
    message: { message: 'For mange forsøg. Prøv igen senere.' }
});

// Google Maps integration endpoints
app.get('/api/business/google-reviews', authenticateToken, googleReviewsLimiter, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user || !user.googlePlaceId) {
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
      console.log('Returnerer cached reviews data');
      
      // Start asynkron opdatering hvis dataene er ældre end 15 minutter
      const cacheStats = businessCache.getTtl(cacheKey);
      const fifteenMinutesAgo = Date.now() - (15 * 60 * 1000);
      
      if (cacheStats && cacheStats < fifteenMinutesAgo) {
        console.log('Cache er ældre end 15 minutter, starter baggrundsopdatering');
        updateCacheInBackground(user, cacheKey).catch(console.error);
      }
      
      return res.json(cachedData);
    }

    // Hvis ingen cache, hent nye data
    const placeDetailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${user.googlePlaceId}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    
    const placeDetailsResponse = await axios.get(placeDetailsUrl, {
      timeout: 5000, // 5 sekunder timeout
      retry: 3, // Antal retry forsøg
      retryDelay: (retryCount) => {
        return retryCount * 1000; // Stigende ventetid mellem forsøg
      }
    });

    if (placeDetailsResponse.data.status === 'REQUEST_DENIED') {
      console.error('Google Places API afviste anmodningen:', placeDetailsResponse.data.error_message);
      
      // Hvis vi har udløbet cache data, brug det som fallback
      const expiredData = businessCache.get(cacheKey, true); // true = få også udløbede værdier
      if (expiredData) {
        console.log('Bruger udløbet cache som fallback');
        return res.json({
          ...expiredData,
          _cached: true,
          _expired: true
        });
      }
      
      return res.status(503).json({ 
        message: 'Kunne ikke hente virksomhedsdata lige nu, prøv igen senere'
      });
    }

    if (!placeDetailsResponse.data.result) {
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

    // Gem i cache med længere TTL
    businessCache.set(cacheKey, responseData, 1800); // 30 minutter
    
    res.json(responseData);
  } catch (error) {
    console.error('Fejl ved hentning af Google reviews:', {
      error: error.message,
      stack: error.stack,
      response: error.response?.data
    });

    // Prøv at bruge udløbet cache som fallback
    const expiredData = businessCache.get(cacheKey, true);
    if (expiredData) {
      console.log('Bruger udløbet cache som fallback efter fejl');
      return res.json({
        ...expiredData,
        _cached: true,
        _expired: true
      });
    }

    res.status(500).json({ 
      message: 'Der opstod en fejl ved hentning af anmeldelser. Prøv igen senere.',
      error: error.message 
    });
  }
});

// Hjælpefunktion til at opdatere cache i baggrunden
async function updateCacheInBackground(user, cacheKey) {
  try {
    const placeDetailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${user.googlePlaceId}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    const response = await axios.get(placeDetailsUrl);
    
    if (response.data.status === 'OK' && response.data.result) {
      const placeDetails = response.data.result;
      const updatedData = {
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
      
      businessCache.set(cacheKey, updatedData, 1800);
      console.log('Cache opdateret i baggrunden');
    }
  } catch (error) {
    console.error('Fejl ved baggrundsopdatering af cache:', error);
  }
}

// Nyt endpoint til at svare på anmeldelser
app.post('/api/business/reviews/:reviewId/reply', authenticateToken, async (req, res) => {
  try {
    const { reviewId } = req.params;
    const { reply } = req.body;
    const user = await User.findById(req.session.userId);

    if (!user || !user.googleAccessToken || !user.googlePlaceId) {
      return res.status(401).json({ 
        message: 'Du skal være logget ind med Google Business Profile for at svare på anmeldelser' 
      });
    }

    // Opret OAuth2 klient
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.NODE_ENV === 'production'
        ? "https://api.tapfeed.dk/api/auth/google-business/callback"
        : "http://localhost:3000/api/auth/google-business/callback"
    );

    oauth2Client.setCredentials({
      access_token: user.googleAccessToken,
      refresh_token: user.googleRefreshToken
    });

    // Opret My Business API klient
    const mybusiness = google.mybusinessbusinessinformation({
      version: 'v1',
      auth: oauth2Client
    });

    // Hent accounts
    const accounts = await mybusiness.accounts.list();
    
    if (!accounts.data.accounts || accounts.data.accounts.length === 0) {
      return res.status(404).json({ message: 'Ingen Google Business konto fundet' });
    }

    const accountName = accounts.data.accounts[0].name;

    // Send svar på anmeldelse via My Business API
    const replyResponse = await mybusiness.locations.reviews.reply({
      name: `${accountName}/locations/${user.googlePlaceId}/reviews/${reviewId}`,
      requestBody: {
        comment: reply
      }
    });

    // Ryd cache for at tvinge en opdatering af anmeldelser
    const cacheKey = `reviews_${user.googlePlaceId}`;
    businessCache.del(cacheKey);

    res.json({ 
      message: 'Svar på anmeldelse gemt succesfuldt',
      reply: replyResponse.data 
    });

  } catch (error) {
    console.error('Fejl ved svar på anmeldelse:', {
      error: error.message,
      response: error.response?.data,
      stack: error.stack
    });

    if (error.response?.status === 401) {
      return res.status(401).json({ 
        message: 'Din Google Business autorisation er udløbet. Log venligst ind igen.',
        needsAuth: true 
      });
    }

    res.status(500).json({ 
      message: 'Der opstod en fejl ved svar på anmeldelsen',
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

// Landing Pages endpoints
app.post('/api/landing-pages', authenticateToken, upload.fields([
  { name: 'logo', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const { 
      title, 
      description, 
      urlPath,
      backgroundColor, 
      buttonColor, 
      buttonTextColor,
      titleColor,
      descriptionColor,
      buttons,
      showTitle,
      socialLinks 
    } = req.body;
    
    // Tjek om URL-stien allerede er i brug
    if (urlPath) {
      const existingPage = await LandingPage.findOne({ urlPath });
      if (existingPage) {
        return res.status(400).json({ 
          message: 'Denne URL-sti er allerede i brug. Vælg venligst en anden.' 
        });
      }
    }
    
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
      urlPath,
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

    await page.save();
    res.status(201).json(page);
  } catch (error) {
    console.error('Fejl ved oprettelse af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved oprettelse af landing page' });
  }
});

app.get('/api/landing-pages', authenticateToken, landingPagesLimiter, async (req, res) => {
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
    console.log('Modtaget opdateringsdata:', req.body);

    // Fjern urlPath fra updates hvis den er tom
    const { urlPath, showTitle, ...otherUpdates } = req.body;
    
    let updates = {};

    // Håndter alle felter fra request body, undtagen dem vi ikke vil have duplikeret
    Object.keys(otherUpdates).forEach(key => {
      if (otherUpdates[key] !== undefined && 
          key !== 'title' && // Ignorer det ekstra titel felt
          key !== 'description' && // Ignorer det ekstra beskrivelse felt
          key !== 'showTitle') { // Ignorer showTitle feltet
        updates[key] = otherUpdates[key];
      }
    });

    // Parse JSON felter hvis de findes
    if (typeof updates.buttons === 'string') {
      try {
        updates.buttons = JSON.parse(updates.buttons);
      } catch (e) {
        console.error('Fejl ved parsing af buttons:', e);
      }
    }

    if (typeof updates.socialLinks === 'string') {
      try {
        updates.socialLinks = JSON.parse(updates.socialLinks);
      } catch (e) {
        console.error('Fejl ved parsing af socialLinks:', e);
      }
    }

    // Håndter fil uploads
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

    // Opret update operation
    const updateOperation = {
      $set: updates
    };

    // Håndter urlPath
    if (!urlPath || urlPath === '') {
      updateOperation.$unset = { urlPath: 1 };
    } else {
      updateOperation.$set.urlPath = urlPath;
    }

    console.log('Forsøger at opdatere med:', updateOperation);

    const updatedPage = await LandingPage.findOneAndUpdate(
      { _id: req.params.id, userId: req.session.userId },
      updateOperation,
      { 
        new: true,
        runValidators: true
      }
    );

    if (!updatedPage) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }

    console.log('Landing page opdateret:', updatedPage);
    res.json(updatedPage);

  } catch (error) {
    console.error('Fejl ved opdatering af landing page:', error);
    res.status(500).json({ 
      message: 'Der opstod en fejl ved opdatering af landing page',
      error: error.message
    });
  }
});

app.delete('/api/landing-pages/:id', authenticateToken, landingPagesLimiter, async (req, res) => {
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
app.get('/api/landing/:id', landingPagesLimiter, async (req, res) => {
  try {
    const page = await LandingPage.findById(req.params.id);
    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }

    // Forbedret viewport og højde håndtering
    const mobileHeightScript = `
      <script>
        function setViewportHeight() {
          // Få den faktiske viewport højde
          const vh = window.innerHeight;
          // Beregn maksimal højde (80% på desktop, 100% på mobile)
          const isMobile = window.innerWidth <= 768;
          const maxHeight = isMobile ? vh : Math.min(vh * 0.8, 800);
          
          // Opdater CSS variabler
          document.documentElement.style.setProperty('--real-vh', vh + 'px');
          document.documentElement.style.setProperty('--max-height', maxHeight + 'px');
          
          // Opdater container højde direkte
          const container = document.querySelector('.landing-page-container');
          if (container) {
            container.style.height = maxHeight + 'px';
            container.style.maxHeight = maxHeight + 'px';
          }
        }

        // Kør ved start
        setViewportHeight();
        
        // Kør når vinduet ændrer størrelse
        let resizeTimer;
        window.addEventListener('resize', () => {
          clearTimeout(resizeTimer);
          resizeTimer = setTimeout(setViewportHeight, 100);
        });

        window.addEventListener('orientationchange', () => {
          setTimeout(setViewportHeight, 200);
        });

        window.addEventListener('load', setViewportHeight);
      </script>
    `;

    // Forbedret CSS styling
    const mobileStyles = `
      ${page.customStyles || ''}
      
      :root {
        --real-vh: 100vh;
        --max-height: 800px;
      }

      html, body {
        margin: 0;
        padding: 0;
        min-height: 100%;
      }

      body {
        display: flex;
        justify-content: center;
        align-items: center;
        background-color: #f5f5f5;
      }

      .landing-page-container {
        width: 100%;
        max-width: 800px;
        height: var(--max-height);
        max-height: var(--max-height);
        overflow-y: auto;
        -webkit-overflow-scrolling: touch;
        position: relative;
        margin: 20px auto;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      }

      .landing-page-content {
        height: 100%;
        width: 100%;
        display: flex;
        flex-direction: column;
      }

      @supports (-webkit-touch-callout: none) {
        .landing-page-container {
          height: -webkit-fill-available;
          max-height: -webkit-fill-available;
        }
      }

      @media screen and (max-width: 768px) {
        body {
          background-color: white;
        }
        
        .landing-page-container {
          margin: 0;
          height: 100vh;
          max-height: var(--real-vh);
          border-radius: 0;
          box-shadow: none;
        }
      }

      @media screen and (min-width: 769px) {
        .landing-page-container {
          background-color: white;
          transition: height 0.3s ease-in-out;
        }
      }
    `;

    // Opdater page styling og scripts
    page.customStyles = mobileStyles;
    page.scripts = mobileHeightScript + (page.scripts || '');

    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

// Landing page preview endpoint - tillader alle origins og ingen rate limiting
app.get('/api/landing/:id', async (req, res) => {
  try {
    const page = await LandingPage.findById(req.params.id);
    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }

    // Tillad CORS for dette endpoint
    const allowedOrigins = process.env.NODE_ENV === 'production' 
      ? ['https://my.tapfeed.dk', 'https://api.tapfeed.dk', 'https://tapfeed.dk']
      : ['http://localhost:3001', 'http://localhost:3000'];

    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
    }

    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

// Password reset endpoints
app.post('/api/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      // For sikkerhed returnerer vi samme besked selvom brugeren ikke findes
      return res.json({ message: 'Hvis en konto med denne email eksisterer, vil der blive sendt et nulstillingslink' });
    }

    // Generer reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 time

    // Gem token i brugerens dokument
    await User.findByIdAndUpdate(user._id, {
      resetPasswordToken: resetToken,
      resetPasswordExpires: resetTokenExpiry
    });

    // Generer reset URL
    const resetUrl = process.env.NODE_ENV === 'production'
      ? `https://my.tapfeed.dk/reset-password/${resetToken}`
      : `http://localhost:3001/reset-password/${resetToken}`;

    // Send email med reset link
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
      }
    });

    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: user.email,
      subject: 'Nulstil din adgangskode - TapFeed',
      html: `
        <p>Hej ${user.username},</p>
        <p>Du har anmodet om at nulstille din adgangskode.</p>
        <p>Klik på linket herunder for at vælge en ny adgangskode:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>Dette link udløber om 1 time.</p>
        <p>Hvis du ikke har anmodet om denne nulstilling, kan du ignorere denne email.</p>
        <p>Venlig hilsen,<br>TapFeed Team</p>
      `
    });

    res.json({ message: 'Hvis en konto med denne email eksisterer, vil der blive sendt et nulstillingslink' });
  } catch (error) {
    console.error('Fejl ved anmodning om nulstilling af adgangskode:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved anmodning om nulstilling af adgangskode' });
  }
});

// Verify reset token
app.get('/api/verify-reset-token/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Ugyldigt eller udløbet nulstillingslink' });
    }

    res.json({ message: 'Token er gyldigt' });
  } catch (error) {
    console.error('Fejl ved verificering af reset token:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved verificering af nulstillingslink' });
  }
});

// Reset password with token
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Ugyldigt eller udløbet nulstillingslink' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update user
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Adgangskode nulstillet succesfuldt' });
  } catch (error) {
    console.error('Fejl ved nulstilling af adgangskode:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved nulstilling af adgangskode' });
  }
});

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

// Konfigurer app indstillinger
app.set('trust proxy', 1);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('MongoDB forbindelse etableret');
})
.catch(err => {
    console.error('MongoDB forbindelsesfejl:', err);
    process.exit(1);
});

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
    console.log('Mongoose forbundet til MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('Mongoose forbindelsesfejl:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('Mongoose afbrudt fra MongoDB');
});

process.on('SIGINT', async () => {
    await mongoose.connection.close();
    process.exit(0);
});

// Dashboard endpoint
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Hent brugerens stands
    const stands = await Stand.find({ userId: user._id }).sort({ createdAt: -1 });

    // Hent brugerens landing pages
    const landingPages = await LandingPage.find({ userId: user._id }).sort({ createdAt: -1 });

    res.json({
      user: {
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
        googlePlaceId: user.googlePlaceId
      },
      stands,
      landingPages
    });
  } catch (error) {
    console.error('Fejl ved hentning af dashboard data:', error);
    res.status(500).json({ 
      message: 'Der opstod en fejl ved hentning af dashboard data',
      error: error.message 
    });
  }
});

// Google Business logout endpoint
app.post('/api/auth/google-business/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Nulstil Google tokens
    user.googleAccessToken = null;
    user.googleRefreshToken = null;
    await user.save();

    // Ryd cache for brugerens anmeldelser
    if (user.googlePlaceId) {
      const cacheKey = `reviews_${user.googlePlaceId}`;
      businessCache.del(cacheKey);
    }

    res.json({ message: 'Logget ud af Google Business Profile' });
  } catch (error) {
    console.error('Fejl ved logout fra Google Business:', error);
    res.status(500).json({ 
      message: 'Der opstod en fejl ved logout fra Google Business Profile',
      error: error.message 
    });
  }
});

// Serve static files fra frontend build
app.use(express.static(path.join(__dirname, 'frontend/build')));

// Handle alle andre routes ved at sende index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/build', 'index.html'));
});

// Landing page viewport height endpoint
app.get('/api/viewport-height', (req, res) => {
  // Send en simpel HTML-side der returnerer viewport højden
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script>
          // Beregn den faktiske viewport højde og send den tilbage til parent
          function sendViewportHeight() {
            const vh = window.innerHeight;
            window.parent.postMessage({ type: 'viewportHeight', height: vh }, '*');
          }
          
          // Send højden ved load og resize
          window.addEventListener('load', sendViewportHeight);
          window.addEventListener('resize', sendViewportHeight);
        </script>
      </head>
      <body style="margin:0;padding:0;">
      </body>
    </html>
  `);
});

// Registrer routes
app.use('/api/landing-pages', landingPagesRouter);
app.use('/api/user', userRouter);
app.use('/api/admin', adminRouter);

// Speciel CORS middleware for landing pages
const landingPageCors = cors({
  origin: '*', // Tillad alle origins for landing pages
  methods: ['GET'],
  allowedHeaders: ['Content-Type']
});

// Landing page endpoints med speciel CORS
app.get('/api/landing/:id', landingPageCors, async (req, res) => {
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

// Start serveren
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server kører på port ${PORT}`);
});

// Admin endpoints
app.get('/api/admin/users/:id/statistics', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    const userId = req.params.id;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Bruger ikke fundet' });
    }

    // Hent alle brugerens stands
    const stands = await Stand.find({ userId: userId });
    
    // Beregn total antal klik
    const totalClicks = stands.reduce((sum, stand) => sum + (stand.clicks || 0), 0);
    
    // Beregn klik over tid (sidste 30 dage)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const clicksOverTime = {};
    stands.forEach(stand => {
      stand.clickHistory.forEach(click => {
        if (click.timestamp >= thirtyDaysAgo) {
          const date = click.timestamp.toISOString().split('T')[0];
          clicksOverTime[date] = (clicksOverTime[date] || 0) + 1;
        }
      });
    });

    // Hent landing pages
    const landingPages = await LandingPage.find({ userId: userId });

    // Hent kategorier
    const categories = await Category.find({ userId: userId });

    // Beregn statistik for stands
    const standsStats = {
      total: stands.length,
      claimed: stands.filter(s => s.status === 'claimed').length,
      unclaimed: stands.filter(s => s.status === 'unclaimed').length,
      withLandingPage: stands.filter(s => s.landingPageId).length,
      withRedirectUrl: stands.filter(s => s.redirectUrl).length,
      byProductType: stands.reduce((acc, stand) => {
        acc[stand.productType] = (acc[stand.productType] || 0) + 1;
        return acc;
      }, {})
    };

    // Beregn aktivitetsstatistik
    const activityStats = {
      lastLogin: user.lastLogin,
      accountCreated: user.createdAt,
      lastStandClaimed: stands.reduce((latest, stand) => {
        if (stand.claimedAt && (!latest || stand.claimedAt > latest)) {
          return stand.claimedAt;
        }
        return latest;
      }, null),
      lastLandingPageCreated: landingPages.length > 0 ? 
        landingPages.reduce((latest, page) => 
          !latest || page.createdAt > latest ? page.createdAt : latest
        , null) : null
    };

    // Samlet statistik
    const statistics = {
      user: {
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
        isAdmin: user.isAdmin,
        hasGoogleBusiness: !!user.googlePlaceId
      },
      stands: standsStats,
      engagement: {
        totalClicks,
        clicksOverTime,
        averageClicksPerStand: stands.length ? (totalClicks / stands.length).toFixed(2) : 0,
        mostClickedStand: stands.reduce((most, stand) => 
          !most || stand.clicks > most.clicks ? stand : most
        , null)
      },
      content: {
        landingPages: landingPages.length,
        categories: categories.length
      },
      activity: activityStats
    };

    res.json(statistics);
  } catch (error) {
    console.error('Fejl ved hentning af brugerstatistik:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af statistik' });
  }
});

// Admin system statistics endpoint
app.get('/api/admin/statistics', authenticateToken, async (req, res) => {
  try {
    // Tjek om brugeren er admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Ingen adgang' });
    }

    // Hent total antal brugere
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ 
      lastLogin: { 
        $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) 
      } 
    });

    // Hent total antal stands og deres status
    const stands = await Stand.find();
    const standsStats = {
      total: stands.length,
      claimed: stands.filter(s => s.status === 'claimed').length,
      unclaimed: stands.filter(s => s.status === 'unclaimed').length,
      totalClicks: stands.reduce((sum, stand) => sum + (stand.clicks || 0), 0)
    };

    // Beregn klik over tid (sidste 30 dage)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const clicksOverTime = {};
    stands.forEach(stand => {
      stand.clickHistory.forEach(click => {
        if (click.timestamp >= thirtyDaysAgo) {
          const date = click.timestamp.toISOString().split('T')[0];
          clicksOverTime[date] = (clicksOverTime[date] || 0) + 1;
        }
      });
    });

    // Hent landing pages statistik
    const totalLandingPages = await LandingPage.countDocuments();
    
    // Beregn brugeraktivitet over tid
    const userSignups = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Beregn produkttype fordeling
    const productTypeDistribution = stands.reduce((acc, stand) => {
      acc[stand.productType] = (acc[stand.productType] || 0) + 1;
      return acc;
    }, {});

    // Samlet statistik
    const statistics = {
      users: {
        total: totalUsers,
        active: activeUsers,
        signupsOverTime: userSignups.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {})
      },
      stands: {
        ...standsStats,
        productTypeDistribution,
        averageClicksPerStand: stands.length ? 
          (standsStats.totalClicks / stands.length).toFixed(2) : 0
      },
      engagement: {
        clicksOverTime,
        totalClicks: standsStats.totalClicks
      },
      content: {
        totalLandingPages,
        averageLandingPagesPerUser: totalUsers ? 
          (totalLandingPages / totalUsers).toFixed(2) : 0
      }
    };

    res.json(statistics);
  } catch (error) {
    console.error('Fejl ved hentning af systemstatistik:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af statistik' });
  }
});

// Kontaktformular endpoint
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Opret email transporter
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
      }
    });

    // Send email
    await transporter.sendMail({
      from: {
        name: 'TapFeed Kontaktformular',
        address: process.env.GMAIL_USER
      },
      replyTo: email,
      to: process.env.GMAIL_USER,
      subject: `Ny kontaktformular besked: ${subject}`,
      html: `
        <h2>Ny besked fra kontaktformularen</h2>
        <p><strong>Navn:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Emne:</strong> ${subject}</p>
        <p><strong>Besked:</strong></p>
        <p>${message}</p>
      `
    });

    // Send autosvar til afsender
    await transporter.sendMail({
      from: {
        name: 'TapFeed Support',
        address: process.env.GMAIL_USER
      },
      to: email,
      subject: 'Tak for din henvendelse - TapFeed',
      html: `
        <p>Hej ${name},</p>
        <p>Tak for din henvendelse. Vi har modtaget din besked og vender tilbage hurtigst muligt.</p>
        <br>
        <p>Med venlig hilsen</p>
        <p>TapFeed Support</p>
      `
    });

    res.json({ message: 'Besked sendt succesfuldt' });
  } catch (error) {
    console.error('Fejl ved afsendelse af kontaktformular:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved afsendelse af beskeden' });
  }
});

// Opdater catch-all route for frontend routes i production
app.get(['/unclaimed/*', '/not-configured/*', '/dashboard/*', '/login', '/register', '/settings'], (req, res) => {
  console.log('Håndterer frontend app route:', {
    path: req.path,
    environment: process.env.NODE_ENV,
    host: req.get('host')
  });
  
  // Send index.html for alle frontend routes
  res.sendFile(path.join(__dirname, 'frontend/build', 'index.html'));
});

// Generel catch-all route som skal være SIDSTE route
app.get('*', (req, res) => {
  console.log('Håndterer ukendt route:', {
    path: req.path,
    environment: process.env.NODE_ENV,
    host: req.get('host')
  });
  
  // I production, tjek om det er en kendt frontend route
  if (process.env.NODE_ENV === 'production') {
    const knownFrontendRoutes = [
      '/unclaimed',
      '/not-configured',
      '/dashboard',
      '/login',
      '/register',
      '/settings'
    ];

    // Hvis stien starter med en kendt frontend route, send index.html
    if (knownFrontendRoutes.some(route => req.path.startsWith(route))) {
      console.log('Sender frontend app for kendt route:', req.path);
      return res.sendFile(path.join(__dirname, 'frontend/build', 'index.html'));
    }
  }
  
  // Hvis ikke en kendt route, send 404
  res.status(404).send('Side ikke fundet');
});

// Flyt static file serving før de specifikke routes
app.use(express.static(path.join(__dirname, 'frontend/build')));

// Tilføj denne route handler lige efter dine API routes men før den generelle catch-all
app.get(['/unclaimed/*', '/not-configured/*'], (req, res) => {
  console.log('Frontend special route match:', {
    path: req.path,
    environment: process.env.NODE_ENV,
    host: req.get('host')
  });
  
  // Send index.html direkte fra build mappen
  const indexPath = path.join(__dirname, 'frontend', 'build', 'index.html');
  console.log('Serving index.html from:', indexPath);
  
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    console.error('index.html not found at:', indexPath);
    res.status(404).send('Frontend application not found');
  }
});

// Serve static files først
app.use(express.static(path.join(__dirname, 'frontend/build')));

// API routes (behold alle eksisterende API routes)

// Frontend routes
app.get([
  '/unclaimed/*',
  '/not-configured/*',
  '/dashboard',
  '/login',
  '/register',
  '/settings',
  '/landing/*'
], (req, res) => {
  console.log('Serving frontend for path:', req.path);
  const indexPath = path.join(__dirname, 'frontend/build', 'index.html');
  console.log('Serving index.html from:', indexPath);
  res.sendFile(indexPath);
});

// Produkt redirect route
app.get('/:standerId([A-Za-z0-9]+)', async (req, res, next) => {
  try {
    const stand = await Stand.findOne({ standerId: req.params.standerId });
    
    if (!stand) {
      console.log('Stand ikke fundet:', req.params.standerId);
      return next();
    }

    const frontendUrl = process.env.NODE_ENV === 'production'
      ? 'https://my.tapfeed.dk'
      : 'http://localhost:3001';

    console.log('Stand fundet:', {
      standerId: stand.standerId,
      status: stand.status,
      configured: stand.configured
    });

    if (stand.status === 'unclaimed') {
      const url = `${frontendUrl}/unclaimed/${stand.standerId}`;
      console.log('Redirecting to unclaimed:', url);
      return res.redirect(302, url);
    }

    if (!stand.configured || (!stand.redirectUrl && !stand.landingPageId)) {
      const url = `${frontendUrl}/not-configured/${stand.standerId}`;
      console.log('Redirecting to not-configured:', url);
      return res.redirect(302, url);
    }

    if (stand.redirectUrl) {
      let redirectUrl = stand.redirectUrl;
      if (!redirectUrl.startsWith('http://') && !redirectUrl.startsWith('https://')) {
        redirectUrl = 'https://' + redirectUrl;
      }
      console.log('Redirecting to external:', redirectUrl);
      stand.clicks = (stand.clicks || 0) + 1;
      await stand.save();
      return res.redirect(302, redirectUrl);
    }

    next();
  } catch (error) {
    console.error('Fejl ved håndtering af produkt redirect:', error);
    next(error);
  }
});

// Final catch-all
app.get('*', (req, res) => {
  console.log('Serving frontend for unknown path:', req.path);
  const indexPath = path.join(__dirname, 'frontend/build', 'index.html');
  console.log('Serving index.html from:', indexPath);
  res.sendFile(indexPath);
});
