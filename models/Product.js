const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    description: {
        type: String,
        required: false
    },
    category: {
        type: String,
        required: false
    },
    stand: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Stand',
        required: true
    }
}, { timestamps: true });

module.exports = mongoose.model('Product', productSchema); 