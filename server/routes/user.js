// server/routes/user.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const User = require('../models/User');

// @route   GET /api/user/profile
// @desc    Get current user profile
// @access  Private
router.get('/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user.toSafeObject());
    } catch (err) {
        console.error('Profile fetch error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// @route   PUT /api/user/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', auth, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Name must be at least 2 characters' });
        }

        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.name = name.trim();
        await user.save();

        res.json({
            message: 'Profile updated successfully',
            user: user.toSafeObject()
        });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// @route   DELETE /api/user/provider/:provider
// @desc    Unlink OAuth provider
// @access  Private
router.delete('/provider/:provider', auth, async (req, res) => {
    try {
        const { provider } = req.params;

        if (!['google', 'facebook'].includes(provider)) {
            return res.status(400).json({ error: 'Invalid provider' });
        }

        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Don't allow unlinking if it's the only provider
        if (user.providers.length <= 1) {
            return res.status(400).json({
                error: 'Cannot unlink the only login method'
            });
        }

        // Remove the provider
        user.providers = user.providers.filter(p => p.provider !== provider);
        await user.save();

        res.json({
            message: `${provider} unlinked successfully`,
            user: user.toSafeObject()
        });
    } catch (err) {
        console.error('Unlink provider error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;