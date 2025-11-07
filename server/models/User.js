// server/models/User.js
const mongoose = require('mongoose');

const providerSchema = new mongoose.Schema({
    provider: {
        type: String,
        enum: ['google', 'facebook'],
        required: true
    },
    providerId: {
        type: String,
        required: true
    },
    email: String,
    connectedAt: {
        type: Date,
        default: Date.now
    }
});

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    avatar: {
        type: String,
        default: ''
    },
    providers: [providerSchema],
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Index for faster OAuth lookups
userSchema.index({ 'providers.provider': 1, 'providers.providerId': 1 });

// Method to check if user has a specific provider
userSchema.methods.hasProvider = function(providerName) {
    return this.providers.some(p => p.provider === providerName);
};

// Method to get safe user data (exclude sensitive info)
userSchema.methods.toSafeObject = function() {
    return {
        id: this._id,
        email: this.email,
        name: this.name,
        avatar: this.avatar,
        role: this.role,
        providers: this.providers.map(p => ({
            provider: p.provider,
            connectedAt: p.connectedAt
        })),
        lastLogin: this.lastLogin,
        createdAt: this.createdAt
    };
};

module.exports = mongoose.model('User', userSchema);