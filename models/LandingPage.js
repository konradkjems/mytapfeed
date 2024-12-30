const mongoose = require('mongoose');

const landingPageSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  urlPath: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^[a-z0-9-]+$/.test(v);
      },
      message: props => `${props.value} er ikke en gyldig URL sti. Brug kun små bogstaver, tal og bindestreger.`
    }
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  logo: {
    type: String // URL til logo i Cloudinary
  },
  backgroundImage: {
    type: String // URL til baggrundsbillede i Cloudinary
  },
  backgroundColor: {
    type: String,
    default: '#ffffff'
  },
  buttonColor: {
    type: String,
    default: '#000000'
  },
  buttonTextColor: {
    type: String,
    default: '#ffffff'
  },
  titleColor: {
    type: String,
    default: '#000000'
  },
  descriptionColor: {
    type: String,
    default: '#000000'
  },
  titleFont: {
    type: String,
    enum: ['Inter', 'Roboto', 'Playfair Display', 'Montserrat', 'Lato', 'Open Sans', 'Raleway', 'Poppins'],
    default: 'Inter'
  },
  descriptionFont: {
    type: String,
    enum: ['Inter', 'Roboto', 'Playfair Display', 'Montserrat', 'Lato', 'Open Sans', 'Raleway', 'Poppins'],
    default: 'Inter'
  },
  buttonFont: {
    type: String,
    enum: ['Inter', 'Roboto', 'Playfair Display', 'Montserrat', 'Lato', 'Open Sans', 'Raleway', 'Poppins'],
    default: 'Inter'
  },
  buttons: [{
    text: String,
    url: String,
    order: Number
  }],
  socialLinks: {
    instagram: String,
    facebook: String,
    tiktok: String,
    youtube: String,
    twitter: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

landingPageSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('LandingPage', landingPageSchema); 