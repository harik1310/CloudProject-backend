const { Client } = require('pg')

//database connection
const client = new Client({
    host : "localhost",
    user : "postgres",
    port : 5432 , 
    password : "1310",
    database : "cq"
})



client.connect();
module.exports = {client}
