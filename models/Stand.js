const mongoose = require('mongoose');

const standSchema = new mongoose.Schema({
    standerId: {
        type: String,
        required: true,
        unique: true
    },
    redirectUrl: {
        type: String
    },
    productType: {
        type: String,
        enum: ['stander', 'sticker', 'kort', 'plate'],
        default: 'stander'
    },
    nickname: {
        type: String
    },
    status: {
        type: String,
        enum: ['unclaimed', 'claimed'],
        default: 'unclaimed'
    },
    configured: {
        type: Boolean,
        default: false
    },
    ownerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    landingPageId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'LandingPage'
    },
    clicks: {
        type: Number,
        default: 0
    },
    clickHistory: [{
        timestamp: {
            type: Date,
            required: true,
            set: function(v) {
                // Konverter til Date objekt hvis det er en string
                return typeof v === 'string' ? new Date(v) : v;
            },
            get: function(v) {
                // Returner som ISO string når vi henter værdien
                return v ? v.toISOString() : null;
            }
        },
        ip: String
    }],
    claimedAt: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true // Tilføj automatisk updatedAt og createdAt
});

module.exports = mongoose.model('Stand', standSchema); 