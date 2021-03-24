require('dotenv').config();
const express = require('express');
const cors = require('cors');
const routes = require('./routes');

const app = express();
app.use(express.json());
app.use(cors());
app.use('/api', routes);
const PORT = process.env.PORT || 3000;

try {
    app.listen(PORT, () => {
        console.log(`Listening on port ${PORT}`);
    });
} catch (error) {
    console.log(`Error in port ${PORT}`, error);
}