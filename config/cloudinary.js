const cloudinary = require('cloudinary').v2;

try {
    if (!process.env.CLOUDINARY_CLOUD_NAME || 
        !process.env.CLOUDINARY_API_KEY || 
        !process.env.CLOUDINARY_API_SECRET) {
        throw new Error('Manglende Cloudinary credentials i miljøvariablerne');
    }

    const config = {
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME.trim(),
        api_key: process.env.CLOUDINARY_API_KEY.trim(),
        api_secret: process.env.CLOUDINARY_API_SECRET.trim(),
        secure: true
    };

    console.log('Forsøger at konfigurere Cloudinary med:', {
        cloud_name: config.cloud_name,
        api_key_length: config.api_key.length,
        api_secret_length: config.api_secret.length
    });

    cloudinary.config(config);

    // Test konfigurationen med async/await
    (async () => {
        try {
            const result = await cloudinary.api.ping();
            console.log('Cloudinary forbindelse testet succesfuldt:', result);
        } catch (error) {
            console.error('Cloudinary ping test fejlede:', {
                error: error.message,
                code: error.http_code,
                details: error
            });
        }
    })();

} catch (error) {
    console.error('Kritisk fejl ved konfiguration af Cloudinary:', error);
    process.exit(1);
}

module.exports = cloudinary; 