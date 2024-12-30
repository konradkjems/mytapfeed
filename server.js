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
const landingPagesRouter = require('./routes/landingPages');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const QRCode = require('qrcode');

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

// Funktion til at tjekke om en request kommer fra et subdomain
const getSubdomain = (host) => {
  const parts = host.split('.');
  if (parts.length > 2) {
    return parts[0];
  }
  return null;
};

// Middleware til at håndtere subdomains
app.use(async (req, res, next) => {
  const subdomain = getSubdomain(req.hostname);
  
  if (subdomain) {
    try {
      const landingPage = await LandingPage.findOne({ subdomain });
      if (landingPage) {
        // Send landing page data
        return res.json(landingPage);
      }
    } catch (error) {
      console.error('Fejl ved håndtering af subdomain:', error);
    }
  }
  next();
});

// Tilføj denne nye route i stedet
app.get('/:urlPath', async (req, res, next) => {
  try {
    const landingPage = await LandingPage.findOne({ urlPath: req.params.urlPath });
    if (landingPage) {
      // Redirect til frontend med landing page ID
      const frontendUrl = process.env.NODE_ENV === 'production'
        ? 'https://my.tapfeed.dk'
        : 'http://localhost:3001';
      return res.redirect(`${frontendUrl}/landing/${landingPage._id}`);
    }
    // Hvis ingen landing page findes, fortsæt til næste route
    next();
  } catch (error) {
    console.error('Fejl ved håndtering af URL path:', error);
    next(error);
  }
});

// Cors setup
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://my.tapfeed.dk', 'https://api.tapfeed.dk', 'https://tapfeed.dk', /\.tapfeed\.dk$/]
        : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Cookie', 'Origin', 'Cache-Control'],
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
        : "http://localhost:3000/api/auth/google/callback",
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
app.get('/api/stands/unclaimed', requireAuth, async (req, res) => {
    try {
        // Tjek om brugeren er admin
        const user = await User.findById(req.session.userId);
        if (!user?.isAdmin) {
            return res.status(403).json({ message: 'Kun administratorer kan se unclaimed produkter' });
        }

        const stands = await Stand.find({ status: 'unclaimed' })
            .sort({ createdAt: -1 });
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

        // Opret alle produkter
        const createdStands = await Stand.insertMany(products);

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
    const { nickname, landingPageId } = req.body;
    
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

    const stand = await Stand.findOneAndUpdate(
      { _id: req.params.id, userId: req.session.userId },
      { 
        nickname,
        landingPageId: landingPageId || null
      },
      { new: true }
    );

    if (!stand) {
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    res.json(stand);
  } catch (error) {
    console.error('Fejl ved opdatering af produkt:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved opdatering af produkt' });
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

// Redirect endpoint for stands
app.get('/:standerId', async (req, res) => {
  try {
    const stand = await Stand.findOne({ standerId: req.params.standerId });
    
    if (!stand) {
      return res.status(404).json({ message: 'Produkt ikke fundet' });
    }

    // Definer frontend URL baseret på miljø
    const frontendUrl = process.env.NODE_ENV === 'production'
      ? 'https://my.tapfeed.dk'
      : 'http://localhost:3001';

    if (stand.status === 'unclaimed') {
      // Hvis produktet ikke er claimed, redirect til claim side
      const loginUrl = `${frontendUrl}/login?redirect=/claim/${stand.standerId}`;
      return res.redirect(loginUrl);
    }

    // Hvis produktet har en landing page, redirect til den
    if (stand.landingPageId) {
      return res.redirect(`${frontendUrl}/landing/${stand.landingPageId}`);
    }

    // Hvis produktet har en redirect URL, brug den
    if (stand.redirectUrl) {
      // Sikr at URL'en starter med http:// eller https://
      const redirectUrl = stand.redirectUrl.startsWith('http') 
        ? stand.redirectUrl 
        : `https://${stand.redirectUrl}`;
      return res.redirect(redirectUrl);
    }

    // Hvis ingen redirect URL eller landing page er sat, redirect til dashboard
    res.redirect(`${frontendUrl}/dashboard`);
  } catch (error) {
    console.error('Fejl ved redirect:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved håndtering af redirect' });
  }
});

// Endpoint til at claime et produkt
app.post('/api/stands/:standerId/claim', authenticateToken, async (req, res) => {
    try {
        // Find produktet og tjek at det er unclaimed
        const stand = await Stand.findOne({ 
            standerId: req.params.standerId,
            status: 'unclaimed'
        });

        if (!stand) {
            return res.status(404).json({ 
                message: 'Produkt ikke fundet eller er allerede aktiveret' 
            });
        }

        // Opdater stand med den nye ejer
        stand.status = 'claimed';
        stand.ownerId = req.user._id;
        stand.claimedAt = new Date();
        await stand.save();

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

        // Opdater antal kliks
        stand.clicks = (stand.clicks || 0) + 1;
        await stand.save();

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

    // Tjek cache først
    const cacheKey = `reviews_${user.googlePlaceId}`;
    const cachedData = businessCache.get(cacheKey);
    if (cachedData) {
      console.log('Returnerer cached reviews data');
      return res.json(cachedData);
    }

    // Hent place details fra Google Places API
    const placeDetailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${user.googlePlaceId}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    const placeDetailsResponse = await axios.get(placeDetailsUrl);

    if (placeDetailsResponse.data.status === 'REQUEST_DENIED') {
      console.error('Google Places API afviste anmodningen:', placeDetailsResponse.data.error_message);
      return res.status(500).json({ message: 'Kunne ikke hente virksomhedsdata' });
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
      reviews: placeDetails.reviews || []
    };

    // Gem i cache i 5 minutter
    businessCache.set(cacheKey, responseData, 300);
    
    res.json(responseData);
  } catch (error) {
    console.error('Fejl ved hentning af Google reviews:', {
      error: error.message,
      stack: error.stack,
      response: error.response?.data
    });
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af anmeldelser' });
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
    
    // Tjek om URL-stien allerede er i brug af en anden landing page
    if (urlPath) {
      const existingPage = await LandingPage.findOne({ 
        urlPath, 
        _id: { $ne: req.params.id } 
      });
      if (existingPage) {
        return res.status(400).json({ 
          message: 'Denne URL-sti er allerede i brug. Vælg venligst en anden.' 
        });
      }
    }

    const updates = {
      title,
      description,
      urlPath,
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
    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page:', error);
    res.status(500).json({ message: 'Der opstod en fejl ved hentning af landing page' });
  }
});

// Landing page preview endpoint - tillader alle origins og ingen rate limiting
app.get('/api/landing-pages/preview/:id', async (req, res) => {
  try {
    const page = await LandingPage.findById(req.params.id);
    if (!page) {
      return res.status(404).json({ message: 'Landing page ikke fundet' });
    }
    // Tillad CORS for dette endpoint
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.json(page);
  } catch (error) {
    console.error('Fejl ved hentning af landing page preview:', error);
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

// Start serveren
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server kører på port ${PORT}`);
});

module.exports = app;
