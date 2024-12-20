const multer = require('multer');

// Multer konfiguration
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // begrænser upload størrelse til 5MB
    }
});

module.exports = upload; 