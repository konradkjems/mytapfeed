const mongoose = require('mongoose');

// Først, drop den eksisterende index
mongoose.connection.on('connected', async () => {
  try {
    await mongoose.connection.db.collection('landingpages').dropIndex('urlPath_1');
    console.log('Eksisterende urlPath index droppet');
  } catch (err) {
    console.log('Ingen eksisterende urlPath index at droppe');
  }
});

const landingPageSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  urlPath: {
    type: String,
    set: v => v === '' ? undefined : v, // Konverterer tom string til undefined
    validate: {
      validator: function(v) {
        if (!v) return true;
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
  showTitle: {
    type: Boolean,
    default: false
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
  },
  titleFontSize: String,
  descriptionFontSize: String,
  buttonFontSize: String,
  titleFontWeight: String,
  descriptionFontWeight: String,
  buttonFontWeight: String
});

// Opret en ny compound index der inkluderer både urlPath og userId
landingPageSchema.index(
  { urlPath: 1, userId: 1 }, 
  { 
    unique: true, 
    sparse: true,
    partialFilterExpression: { urlPath: { $exists: true, $ne: null, $ne: '' } }
  }
);

landingPageSchema.on('index', function(err) {
  if (err) {
    console.error('Index error:', err);
  }
});

landingPageSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('LandingPage', landingPageSchema); 