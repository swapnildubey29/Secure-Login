const mysql = require("mysql2")

const db = mysql.createConnection({
  host: "localhost",
    user: "root",
    password: "@Swapnil29",
    database: "adminpannel",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err.stack)
    return;
  }
  console.log("Connected to the database as id " + db.threadId)
})

module.exports = db;
