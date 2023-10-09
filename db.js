const mongoose = require('mongoose')
require('dotenv').config();


mongoose.connect(process.env.MONGO_URI,{
    dbName: process.env.DB_NAME
}).then(
    () => {
        console.log('Connected to database');
    }
).catch((err) => {
    console.log('Error connecting to database ' + err);
})
