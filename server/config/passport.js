// server/config/passport.js
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const User = require('../models/User');

module.exports = function(passport) {

    // Serialize user for session
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // Deserialize user from session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });

    // Google OAuth Strategy
    passport.use(new GoogleStrategy({
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/api/auth/google/callback',
            scope: ['profile', 'email']
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const email = profile.emails[0].value;
                const providerId = profile.id;

                // Check if user exists
                let user = await User.findOne({
                    'providers.provider': 'google',
                    'providers.providerId': providerId
                });

                if (user) {
                    // Update last login
                    user.lastLogin = new Date();
                    await user.save();
                    return done(null, user);
                }

                // Check if user exists with same email (link accounts)
                user = await User.findOne({ email });

                if (user) {
                    // Add Google provider to existing user
                    user.providers.push({
                        provider: 'google',
                        providerId,
                        email,
                        connectedAt: new Date()
                    });
                    user.lastLogin = new Date();
                    await user.save();
                    return done(null, user);
                }

                // Create new user
                user = await User.create({
                    email,
                    name: profile.displayName,
                    avatar: profile.photos[0]?.value || '',
                    providers: [{
                        provider: 'google',
                        providerId,
                        email,
                        connectedAt: new Date()
                    }],
                    role: 'user',
                    lastLogin: new Date()
                });

                done(null, user);
            } catch (err) {
                console.error('Google OAuth Error:', err);
                done(err, null);
            }
        }));

    // Facebook OAuth Strategy
    passport.use(new FacebookStrategy({
            clientID: process.env.FACEBOOK_APP_ID,
            clientSecret: process.env.FACEBOOK_APP_SECRET,
            callbackURL: '/api/auth/facebook/callback',
            profileFields: ['id', 'emails', 'name', 'picture.type(large)']
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const email = profile.emails[0].value;
                const providerId = profile.id;

                // Check if user exists
                let user = await User.findOne({
                    'providers.provider': 'facebook',
                    'providers.providerId': providerId
                });

                if (user) {
                    user.lastLogin = new Date();
                    await user.save();
                    return done(null, user);
                }

                // Check if user exists with same email
                user = await User.findOne({ email });

                if (user) {
                    user.providers.push({
                        provider: 'facebook',
                        providerId,
                        email,
                        connectedAt: new Date()
                    });
                    user.lastLogin = new Date();
                    await user.save();
                    return done(null, user);
                }

                // Create new user
                user = await User.create({
                    email,
                    name: `${profile.name.givenName} ${profile.name.familyName}`,
                    avatar: profile.photos[0]?.value || '',
                    providers: [{
                        provider: 'facebook',
                        providerId,
                        email,
                        connectedAt: new Date()
                    }],
                    role: 'user',
                    lastLogin: new Date()
                });

                done(null, user);
            } catch (err) {
                console.error('Facebook OAuth Error:', err);
                done(err, null);
            }
        }));
};