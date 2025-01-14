require('dotenv').config()
const express = require('express')
const mysql = require('./config/db')
const app = express()
const routes = require('./routes/index')
const cookieParser = require('cookie-parser')
const bodyparser = require('body-parser')

app.use(bodyparser.json());
app.use(bodyparser.urlencoded({extended: true}));

//File Configuration
app.set('view engine', 'ejs')
app.set('views', __dirname + '/views')
app.use('/assets',express.static(__dirname + '/views/assets'))
app.use(cookieParser())
app.use('/', routes)

//Cookie configuration
app.get('/getcookie',async function(req,res){
    res.send(await req.cookies)
})

//Listen
mysql.query('SELECT 1', (err) =>{
     if(err){
        console.err("Error testing MySQL connection:", err.message)
        return;
     }
     console.log("MySQL DB Connected")
     const port = process.env.PORT
     app.listen(port, () => {
        console.log(`Server is running on ${port}`)
     })
})