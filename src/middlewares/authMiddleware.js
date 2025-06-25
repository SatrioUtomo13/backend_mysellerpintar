const jwt = require('jsonwebtoken')
const User = require('../models/userModel')

exports.protect = async (req, res, next) => {
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' })
    }

    const token = authHeader.split(' ')[1]

    try {
        // Token verify
        const decode = jwt.verify(token, process.env.JWT_SECRET)

        // Get user from databse
        const user = await User.findById(decode.userId).select('username role')

        if (!user) {
            return res.status(404).json({ message: 'User not found' })
        }

        // insert to req user
        req.user = {
            id: user._id,
            username: user.username,
            role: user.role
        }

        next()
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' })
    }
}