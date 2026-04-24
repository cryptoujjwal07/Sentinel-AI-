const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    });

    console.log(`✅  MongoDB Connected: ${conn.connection.host}`);
    console.log(`📦  Database: ${conn.connection.name}`);

    // Handle connection events
    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️   MongoDB disconnected. Attempting to reconnect...');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('✅  MongoDB reconnected successfully');
    });

    mongoose.connection.on('error', (err) => {
      console.error('❌  MongoDB connection error:', err.message);
    });

  } catch (error) {
    console.error('❌  MongoDB Connection Failed:', error.message);
    process.exit(1);
  }
};

module.exports = connectDB;
