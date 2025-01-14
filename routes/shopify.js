const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const User = require('../models/User');
const { sendWelcomeEmail } = require('../utils/emailService');
const axios = require('axios');

// API konfiguration
const API_BASE_URL = 'https://api.seal-subscriptions.com/v1';
const API_TOKEN = process.env.SEAL_API_TOKEN;
const API_SECRET = process.env.SEAL_API_SECRET;

// Hjælpefunktion til at generere HMAC signatur
const generateHmacSignature = (payload) => {
    const hmac = crypto.createHmac('sha256', API_SECRET);
    hmac.update(JSON.stringify(payload));
    return hmac.digest('hex');
};

// Hent abonnementsdetaljer
router.get('/subscription/:subscriptionId', async (req, res) => {
    try {
        const { subscriptionId } = req.params;
        const timestamp = Math.floor(Date.now() / 1000);
        const payload = { timestamp };
        
        const response = await axios.get(`${API_BASE_URL}/subscriptions/${subscriptionId}`, {
            headers: {
                'Authorization': `Bearer ${API_TOKEN}`,
                'X-Seal-Timestamp': timestamp,
                'X-Seal-Signature': generateHmacSignature(payload)
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Fejl ved hentning af abonnementsdetaljer:', error);
        res.status(500).json({ 
            message: 'Der opstod en fejl ved hentning af abonnementsdetaljer',
            error: error.message 
        });
    }
});

// Hent alle aktive abonnementer
router.get('/subscriptions/active', async (req, res) => {
    try {
        const timestamp = Math.floor(Date.now() / 1000);
        const payload = { timestamp };
        
        const response = await axios.get(`${API_BASE_URL}/subscriptions?status=active`, {
            headers: {
                'Authorization': `Bearer ${API_TOKEN}`,
                'X-Seal-Timestamp': timestamp,
                'X-Seal-Signature': generateHmacSignature(payload)
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Fejl ved hentning af aktive abonnementer:', error);
        res.status(500).json({ 
            message: 'Der opstod en fejl ved hentning af aktive abonnementer',
            error: error.message 
        });
    }
});

// Verify Shopify webhook signature
const verifyShopifyWebhook = (req, res, next) => {
    try {
        const hmac = req.headers['x-shopify-hmac-sha256'];
        const topic = req.headers['x-shopify-topic'];
        const shop = req.headers['x-shopify-shop-domain'];
        
        if (!hmac || !topic || !shop) {
            return res.status(401).send('Ugyldige headers');
        }

        const rawBody = JSON.stringify(req.body);
        const hash = crypto
            .createHmac('sha256', process.env.SHOPIFY_WEBHOOK_SECRET)
            .update(rawBody, 'utf8')
            .digest('base64');

        if (hash !== hmac) {
            return res.status(401).send('Ugyldig signatur');
        }

        next();
    } catch (error) {
        console.error('Webhook verifikationsfejl:', error);
        res.status(500).send('Intern serverfejl');
    }
};

// Handle subscription creation
router.post('/subscription/created', verifyShopifyWebhook, async (req, res) => {
    try {
        const { 
            customer: { id: customerId, email },
            subscription: { id: subscriptionId, status, plan_name }
        } = req.body;

        // Find eller opret bruger
        let user = await User.findOne({ email: email.toLowerCase() });
        let tempPassword;
        
        if (!user) {
            // Opret ny bruger med midlertidig adgangskode
            tempPassword = crypto.randomBytes(10).toString('hex');
            user = new User({
                username: email.split('@')[0].toLowerCase(),
                email: email.toLowerCase(),
                password: tempPassword,
                shopifyCustomerId: customerId,
                shopifySubscriptionId: subscriptionId,
                subscriptionStatus: 'active',
                subscriptionPlan: plan_name.toLowerCase().includes('starter') ? 'starter' : 'gratis',
                subscriptionStartDate: new Date(),
                subscriptionEndDate: null // Vil blive opdateret ved fornyelse
            });
            await user.save();

            // Send velkomst email med login information
            await sendWelcomeEmail(user, tempPassword);
        } else {
            // Opdater eksisterende bruger
            user.shopifyCustomerId = customerId;
            user.shopifySubscriptionId = subscriptionId;
            user.subscriptionStatus = 'active';
            user.subscriptionPlan = plan_name.toLowerCase().includes('starter') ? 'starter' : 'gratis';
            user.subscriptionStartDate = new Date();
            await user.save();
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('Fejl ved håndtering af subscription created webhook:', error);
        res.status(500).send('Intern serverfejl');
    }
});

// Handle subscription cancellation
router.post('/subscription/cancelled', verifyShopifyWebhook, async (req, res) => {
    try {
        const { 
            subscription: { id: subscriptionId }
        } = req.body;

        const user = await User.findOne({ shopifySubscriptionId: subscriptionId });
        
        if (user) {
            user.subscriptionStatus = 'cancelled';
            user.subscriptionEndDate = new Date();
            await user.save();
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('Fejl ved håndtering af subscription cancelled webhook:', error);
        res.status(500).send('Intern serverfejl');
    }
});

// Handle subscription renewal
router.post('/subscription/renewed', verifyShopifyWebhook, async (req, res) => {
    try {
        const { 
            subscription: { id: subscriptionId, next_billing_date }
        } = req.body;

        const user = await User.findOne({ shopifySubscriptionId: subscriptionId });
        
        if (user) {
            user.subscriptionStatus = 'active';
            user.subscriptionEndDate = new Date(next_billing_date);
            await user.save();
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('Fejl ved håndtering af subscription renewed webhook:', error);
        res.status(500).send('Intern serverfejl');
    }
});

module.exports = router; 