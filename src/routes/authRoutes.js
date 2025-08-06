const express = require('express')
const { body, validationResult } = require('express-validator')
const bcrypt = require('bcryptjs')
const User = require('../models/User')
const router = express.Router()
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { sendEmailNotification } = require('../services/notificationService')

// POST /api/auth/register
router.post('/register', [
    body('username')
        .isAlphanumeric().withMessage('Username must be alphanumeric')
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('email')
        .isEmail().withMessage('Invalid email'),
    body('password')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { username, email, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create and save user
        const user = new User({ username, email, password: hashedPassword });
        await user.save();

        // [Later] TODO: Send confirmation email via notification service
        // sendEmailNotification({
        //     to: user.email,
        //     subject: 'Welcome to our App!',
        //     text: `Hi ${user.username}, thanks for registering!`,
        // }).catch(err => {
        //     console.error('Failed to send registration email: ', err.message)
        // })

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        next(error);
    }
});

router.post('/login', [
    body('email').isEmail().withMessage('Invalid Email'),
    body('password').exists().withMessage('Password is required')
], async (req, res, next) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    try {
        const { email, password } = req.body

        const user = await User.findOne({ email })
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // check pwd
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(401).json({
                message: 'Invalid credentials'
            })
        }

        // create JWT payload and sign token
        const payload = {
            userId: user._id,
            email: user.email
        }

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '1h'
        })

        res.json({ token })
    } catch (error) {
        next(error)
    }
})

router.post('/request-password-reset', [
    body('email').isEmail().withMessage('Valid email required')
], async (req, res, next) => {
    try {
        const { email } = req.body
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(200).json({
                message: 'If an account exists, a reset email has been sent'
            })
        }

        const token = crypto.randomBytes(32).toString('hex')

        user.resetPasswordToken = token
        user.resetPasswordExpires = Date.now() + 3600000 // 1hr

        await user.save()

        // await sendEmailNotification({
        //     to: user.email,
        //     subject: 'Password Reset Request',
        //     text: `You requested a password reset, here's the token: ${token}`
        // })

        res.json({ message: 'If an account exists, a reset email has been sent.' });
    } catch (error) {
        next(error);
    }
})

// POST /api/auth/reset-password
router.post('/reset-password', [
    body('token').exists().withMessage('Token is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be 6+ chars'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
        const { token, password } = req.body;

        // Find user by valid token & expiry
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Clear reset token and expiry
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        // await sendEmailNotification({
        //     to: user.email,
        //     subject: 'Password Reset Successful',
        //     text: 'Your password has been reset successfully.',
        // });

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        next(error);
    }
});

module.exports = router;
