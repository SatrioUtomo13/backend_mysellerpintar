const User = require('../models/userModel')
const bcrypt = require('bcryptjs')

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