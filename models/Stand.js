const mongoose = require('mongoose');

const clickHistorySchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now
    },
    ip: String
});

const standSchema = new mongoose.Schema({
    standerId: {
        type: String,
        required: true,
        unique: true
    },
    nickname: {
        type: String,
        required: false
    },
    redirectUrl: {
        type: String,
        required: false
    },
    productType: {
        type: String,
        enum: ['stander', 'sticker', 'kort', 'plate'],
        required: true
    },
    status: {
        type: String,
        enum: ['unclaimed', 'claimed'],
        default: 'unclaimed'
    },
    ownerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false
    },
    categoryId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category'
    },
    order: {
        type: Number,
        default: 0
    },
    clicks: {
        type: Number,
        default: 0
    },
    clickHistory: [clickHistorySchema],
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Stand', standSchema); 