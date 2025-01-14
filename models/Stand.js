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
            default: Date.now
        }
    }],
    claimedAt: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Stand', standSchema); 