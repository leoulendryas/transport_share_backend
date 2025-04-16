const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,             // e.g., smtp.gmail.com
  port: parseInt(process.env.EMAIL_PORT),   // 465 for SSL
  secure: true,                              // true because port 465 uses SSL
  auth: {
    user: process.env.EMAIL_USER,           // your Gmail
    pass: process.env.EMAIL_PASSWORD        // your Gmail App Password
  }
});

// Optional: Verify connection
transporter.verify((error, success) => {
  if (error) {
    console.error('Nodemailer connection error:', error);
  } else {
    console.log('✅ Nodemailer is ready to send emails');
  }
});

module.exports = transporter;
