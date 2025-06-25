const User = require('../models/userModel')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

exports.register = async (req, res) => {
    const { username, password, role } = req.body

    // Validate request
    if (!username || !password || !role) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ username })
        if (existingUser) {
            return res.status(409).json({ message: 'User already exists' })
        }

        // Encrypt password
        const hashedPassword = await bcrypt.hash(password, 10)
        const user = await User.create({
            username,
            password: hashedPassword,
            role
        })

        // Format response
        const responseUser = {
            username: user.username,
            password: user.password,
            role: user.role,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }

        res.status(201).json(responseUser)
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message })
    }
}

exports.login = async (req, res) => {
    const { username, password } = req.body

    // Validate request
    if (!username || !password) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    try {
        const user = await User.findOne({ username })
        const isMatch = await bcrypt.compare(password, user.password)

        // Check user
        if (!user || !isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' })
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        )

        res.json({ token })
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message })
    }
}

exports.getProfile = (req, res) => {
    const { id, username, role } = req.user

    res.json({ id, username, role })
}