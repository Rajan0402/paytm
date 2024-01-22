const express = require("express")
const router = express.Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const authMiddleware = require('../authMiddleware')
const { updateBody, signInBody, signUpBody, User } = require('../models/user')

router.route("/signin")
  .get(async (req, res) => {
    const parsedData = signInBody.safeParse(req.body)
    if (!parsedData.success) res.json({ message: parsedData.error })

    const userExist = await User.findOne({ username: parsedData.username }).exec()
    if (!userExist) res.status(404).json({ message: "User does not exist" })

    try {
      const pwdMatch = await bcrypt.compare(parsedData.password, userExist.hashedpwd)
      if (!pwdMatch) res.status(401).json({ message: "Wrong password" })

      const token = jwt.sign({ username }, process.env.ACCESS_JWT_SECRET, { expiresIn: "20m" })

      const refresh_token = jwt.sign({ username }, process.env.REFRESH_JWT_SECRET, { expiresIn: "7d" })
      userExist.refresh_token = refresh_token;
      userExist.save()

      res.json({ token })

    } catch (err) {
      res.json({ Error: err })
    }
  })

router.route("/signup")
  .post(async (req, res) => {
    const parsedData = signUpBody.safeParse(req.body)
    if (!parsedData.success) res.json({ message: parsedData.error })

    const userExist = await User.findOne({ username: parsedData.username }).exec()
    if (userExist) res.status(409).json({ message: "User already exist" })

    try {
      const hashedpwd = await bcrypt.hash(parsedData.password, 10)

      await User.create({
        username: parsedData.username,
        password: hashedpwd,
        firstname: parsedData.firstname,
        lastname: parsedData.lastname
      })

      res.json({ message: "User created successfully" })
    } catch (err) {
      res.json({ Error: err })
    }
  })

router.route('/')
  .put(authMiddleware, async (req, res) => {
    const parsedData = updateBody.safeParse(req.body)
    if (!parsedData.success) res.status(411).json({ message: parsedData.error })

    await User.updateOne({ id: req.body.id }, req.body)

    res.json({ message: "Update successful" })
  })

router.route('/bulk')
  .get(authMiddleware, async (req, res) => {
    const filter = req.query.filter

    const users = await User.find({
      $or: [{
        firstname: {
          "$regex": filter
        }
      }, {
        lastname: {
          "$regex": filter
        }
      }]
    }, 'username firstname lastname _id')

    // both are same, above query will include username firstname lastname _id and below one will exclude password and refresh_token
    // const users = await User.find({
    //   $or:[{
    //     firstname:{
    //       "$regex": filter
    //     }
    //   },{
    //     lastname:{
    //       "$regex": filter
    //     }
    //   }]
    // }, {password: 0, refresh_token: 0})

    res.json({ users })
  })

module.exports = router