// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Brugernavn er påkrævet'],
        unique: true,
        trim: true,
        lowercase: true,
        minlength: [3, 'Brugernavn skal være mindst 3 tegn'],
        maxlength: [50, 'Brugernavn må højst være 50 tegn']
    },
    email: {
        type: String,
        required: [true, 'Email er påkrævet'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Indtast venligst en gyldig email adresse']
    },
    password: {
        type: String,
        required: [true, 'Adgangskode er påkrævet'],
        minlength: [6, 'Adgangskode skal være mindst 6 tegn']
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    isBlocked: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    googleId: String,
    googlePlaceId: {
        type: String,
        default: null
    },
    googleAccessToken: {
        type: String,
        default: null
    },
    googleRefreshToken: {
        type: String,
        default: null
    },
    profileImage: {
        type: String,
        default: 'https://res.cloudinary.com/da6jy4nml/image/upload/v1/defaults/default-avatar.png'
    }
}, {
    timestamps: true
});

// Password hashing middleware
userSchema.pre('save', async function(next) {
    try {
        if (!this.isModified('password')) {
            return next();
        }

        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Metode til at sammenligne passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw error;
    }
};

// Slet den eksisterende model hvis den findes
if (mongoose.models.User) {
    delete mongoose.models.User;
}

// Opret modellen på ny
const User = mongoose.model('User', userSchema);

module.exports = User;
