const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

const sendWelcomeEmail = async (user, password) => {
    const baseUrl = process.env.NODE_ENV === 'production' 
        ? 'https://my.tapfeed.dk' 
        : 'http://localhost:3000';

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Velkommen til TapFeed',
        html: `
            <h1>Velkommen til TapFeed!</h1>
            <p>Din konto er blevet oprettet med følgende oplysninger:</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Midlertidig adgangskode:</strong> ${password}</p>
            <p>Du kan logge ind her: <a href="${baseUrl}/login">${baseUrl}/login</a></p>
            <p>Af sikkerhedsmæssige årsager anbefaler vi, at du ændrer din adgangskode efter første login.</p>
            <br>
            <p>Med venlig hilsen</p>
            <p>TapFeed-teamet</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Velkomst email sendt til:', user.email);
    } catch (error) {
        console.error('Fejl ved afsendelse af velkomst email:', error);
        throw error;
    }
};

module.exports = {
    sendWelcomeEmail
}; 