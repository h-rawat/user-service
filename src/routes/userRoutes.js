const express = require('express')
const authenticateToken = require('../middleware/authMiddleware')
const User = require('../models/User')
const { body, validationResult } = require('express-validator')

const router = express.Router()

router.get('/profile', authenticateToken, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId).select('-password')
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user)
    } catch (error) {
        next(error)
    }
})

router.put('/profile', [
    authenticateToken,
    body('username').optional().isAlphanumeric().withMessage('Username must be alphanumeric').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('email').optional().isEmail().withMessage('Invalid email'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const updateFields = {};
        if (req.body.username) updateFields.username = req.body.username;
        if (req.body.email) updateFields.email = req.body.email;

        const updatedUser = await User.findByIdAndUpdate(req.user.userId, updateFields, { new: true }).select('-password');
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(updatedUser);
    } catch (error) {
        next(error);
    }
});

module.exports = router