const express = require('express')
const router = express.Router()
const { register, login, getProfile } = require('../controllers/authController')
const { protect } = require('../middlewares/authMiddleware')

router.post('/register', register)
router.post('/login', login)

// Protected routes
router.get('/profile', protect, getProfile)

module.exports = router