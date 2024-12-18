const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const ResetToken = require('../models/ResetToken');
const createTransporter = require('../config/email');

// Anmod om nulstilling af adgangskode
router.post('/request-reset', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('Modtaget email anmodning for:', email);
        
        const user = await User.findOne({ email });
        console.log('Fundet bruger:', user ? 'Ja' : 'Nej');

        if (!user) {
            return res.status(404).json({ 
                message: 'Hvis denne email eksisterer i vores system, vil du modtage en email med instruktioner' 
            });
        }

        // Generer unik token
        const token = crypto.randomBytes(32).toString('hex');
        console.log('Genereret token');
        
        // Gem token i databasen
        await ResetToken.create({
            userId: user._id,
            token: token
        });
        console.log('Token gemt i database');

        // Opret email transporter
        const transporter = createTransporter();
        console.log('Email transporter oprettet');

        // Send email med nulstillingslink
        const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;
        const mailOptions = {
            from: {
                name: 'TapFeed Support',
                address: 'support@tapfeed.dk'
            },
            replyTo: 'support@tapfeed.dk',
            to: user.email,
            subject: 'Nulstil din TapFeed adgangskode',
            html: `
                <h1>Nulstil din adgangskode</h1>
                <p>Du har anmodet om at nulstille din adgangskode.</p>
                <p>Klik på linket herunder for at nulstille din adgangskode:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p>Dette link udløber om 1 time.</p>
                <p>Hvis du ikke har anmodet om at nulstille din adgangskode, kan du ignorere denne email.</p>
                <br>
                <p>Med venlig hilsen</p>
                <p>TapFeed Support</p>
            `
        };

        console.log('Forsøger at sende email med følgende konfiguration:', {
            from: mailOptions.from,
            replyTo: mailOptions.replyTo,
            to: mailOptions.to,
            subject: mailOptions.subject
        });

        await transporter.sendMail(mailOptions);
        console.log('Email sendt succesfuldt');

        res.json({ 
            message: 'Hvis denne email eksisterer i vores system, vil du modtage en email med instruktioner' 
        });

    } catch (error) {
        console.error('Password reset request error:', error);
        console.error('Detaljeret fejl:', {
            name: error.name,
            message: error.message,
            code: error.code,
            command: error.command,
            stack: error.stack
        });
        res.status(500).json({ 
            message: 'Der opstod en fejl ved behandling af din anmodning' 
        });
    }
});

// Verificer reset token
router.get('/verify-reset-token/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const resetToken = await ResetToken.findOne({ token });

        if (!resetToken) {
            return res.status(400).json({ 
                message: 'Ugyldigt eller udløbet nulstillingslink' 
            });
        }

        res.json({ 
            message: 'Token er gyldigt' 
        });

    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({ 
            message: 'Der opstod en fejl ved verificering af token' 
        });
    }
});

// Nulstil adgangskode
router.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        // Find token i database
        const resetToken = await ResetToken.findOne({ token });
        if (!resetToken) {
            return res.status(400).json({ 
                message: 'Ugyldigt eller udløbet nulstillingslink' 
            });
        }

        // Find bruger og opdater adgangskode
        const user = await User.findById(resetToken.userId);
        if (!user) {
            return res.status(404).json({ 
                message: 'Bruger ikke fundet' 
            });
        }

        // Hash ny adgangskode
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        // Slet reset token
        await ResetToken.deleteOne({ _id: resetToken._id });

        res.json({ 
            message: 'Din adgangskode er blevet opdateret' 
        });

    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ 
            message: 'Der opstod en fejl ved nulstilling af adgangskoden' 
        });
    }
});

module.exports = router; 