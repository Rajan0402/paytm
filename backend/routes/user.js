const express = require("express")
const router = express.Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const authMiddleware = require('../authMiddleware')
const { updateBody, signInBody, signUpBody, User } = require('../models/user')
const { Account } = require('../models/account')

router.route("/signup")
  .post(async (req, res) => {
    const parsedData = signUpBody.safeParse(req.body)
    if (!parsedData.success) res.json({ message: parsedData.error })

    const userExist = await User.findOne({ username: parsedData.data.username }).exec()
    if (userExist) res.status(409).json({ message: "User already exist" })

    try {
      const hashedpwd = await bcrypt.hash(parsedData.data.password, 10)

      const user = await User.create({
        username: parsedData.data.username,
        password: hashedpwd,
        firstname: parsedData.data.firstname,
        lastname: parsedData.data.lastname
      })

      const userAccount = await Account.create({
        userId: user._id,
        balance: Math.floor(Math.random() * 10000) + 1
      })

      res.json({ message: `User created successfully with \u20B9${userAccount.balance}` })
    } catch (err) {
      res.json({ Error1: err })
    }
  })

router.route("/signin")
  .get(async (req, res) => {
    const parsedData = signInBody.safeParse(req.body)
    if (!parsedData.success) res.json({ message: parsedData.error })

    const userExist = await User.findOne({ username: parsedData.data.username }).exec()
    if (!userExist) res.status(404).json({ message: "User does not exist" })

    try {
      const pwdMatch = await bcrypt.compare(parsedData.data.password, userExist.password)
      if (!pwdMatch) res.status(401).json({ message: "Wrong password" })

      const token = jwt.sign({ userId: userExist._id }, process.env.ACCESS_JWT_SECRET, { expiresIn: "20m" })

      const refresh_token = jwt.sign({ userId: userExist._id }, process.env.REFRESH_JWT_SECRET, { expiresIn: "7d" })
      userExist.refresh_token = refresh_token;
      userExist.save()

      res.json({ token })

    } catch (err) {
      res.json({ Error: err })
    }
  })


router.route('/')
  .put(authMiddleware, async (req, res) => {
    const parsedData = updateBody.safeParse(req.body)
    if (!parsedData.success) res.status(411).json({ message: parsedData.error })

    await User.updateOne({ id: parsedData.data.id }, req.body)

    res.json({ message: "Update successful" })
  })

router.route('/bulk')
  .get(authMiddleware, async (req, res) => {
    const filter = req.query.filter

    const users = await User.find({
      $or: [{
        firstname: {
          "$regex": filter.toLowerCase()
        }
      }, {
        lastname: {
          "$regex": filter.toLowerCase()
        }
      }]
    }, { password: 0, refresh_token: 0 }) // last object to exclude password and refresh_token when fetching
    console.log(users)

    res.json({ users })
  })

module.exports = router