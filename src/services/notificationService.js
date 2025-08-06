const axios = require('axios')

const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:4000'

async function sendEmailNotification(emailPayload) {
    try {
        const response = await axios.post(`${NOTIFICATION_SERVICE_URL}/notify/email`, emailPayload)
        return response.data
    } catch (error) {
        console.error('Error sending email via notification service: ', error.message)
        throw new Error('Notification service error')
    }
}

module.exports = {
    sendEmailNotification
}