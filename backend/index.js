require("dotenv").config()
const express = require("express")
const app = express()
const cors = require("cors")
const mongoose = require("mongoose")
const connectDB = require("./config")
const mainRouter = require("./routes/index")
const port = process.env.PORT || 30000

connectDB()

app.use(cors())
app.use(express.json())

app.use("/api/v1", mainRouter)

app.listen(port, () => {
  console.log(`Server listening on port ${port}`)
})