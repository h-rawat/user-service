require('dotenv').config()
const express = require('express')
const morgan = require('morgan')
const helmet = require('helmet')
const cors = require('cors')
const swaggerUi = require('swagger-ui-express')
const swaggerSpec = require('./docs/swagger')
const userRoutes = require('./routes/userRoutes')
const authRoutes = require('./routes/authRoutes')
const errorHandler = require('./middleware/errorHandler')
const connectDB = require('./utils/db')

connectDB()
const app = express()

app.use(express.json())
app.use(cors())
app.use(helmet())
app.use(morgan('dev'))
app.use('/api/users', userRoutes)
app.use('/api/auth', authRoutes)
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))

app.use(errorHandler)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`User service running on port ${PORT}`)
})