/**
 * User Model
 * Handles both local (email/password) and Google authentication
 * Supports role-based access control
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters'],
      maxlength: [30, 'Username cannot exceed 30 characters'],
    },
    name: {
      type: String,
      trim: true,
      default: null,
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email'],
    },
    password: {
      type: String,
      minlength: [6, 'Password must be at least 6 characters'],
      select: false, // Don't return password by default
      // Password is required only for local auth (validated in controller)
    },
    googleId: {
      type: String,
      unique: true,
      sparse: true, // Allows multiple null values (only Google users have this)
      default: null,
    },
    authType: {
      type: String,
      enum: ['local', 'google'],
      default: 'local',
    },
    role: {
      type: String,
      enum: ['admin', 'analyst', 'viewer'],
      default: 'analyst',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
      default: null,
    },
    avatar: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// ─── Hash password before saving (only for local auth) ──────────────────────
userSchema.pre('save', async function (next) {
  // Skip if password not modified or not present (Google auth users)
  if (!this.password || !this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// ─── Compare plain password with hashed password ─────────────────────────────
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.password) return false; // Google auth users have no password
  return await bcrypt.compare(candidatePassword, this.password);
};

// ─── Remove sensitive fields from JSON output ─────────────────────────────────
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
