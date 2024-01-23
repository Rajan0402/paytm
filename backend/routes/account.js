const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const authMiddleware = require('../authMiddleware')
const { Account, transferBody } = require('../models/account')
const { User } = require('../models/user')

router.route('/balance')
  .get(authMiddleware, async (req, res) => {
    const userId = req.userId
    const accoutDetails = await Account.findOne({ userId }).exec()

    res.json({ balance: accoutDetails.balance })
  })

router.route('/transfer')
  .post(authMiddleware, async (req, res) => {
    const session = await mongoose.startSession()

    try {
      session.startTransaction()
      const parsedData = transferBody.safeParse(req.body)
      if (!parsedData.success) res.json({ Error: parsedData.error })

      const senderAccountDetails = await Account.findOne({ userId: req.userId }).session(session)
      if (senderAccountDetails.balance < parsedData.data.amount) {
        session.abortTransaction()
        res.status(400).json({ message: "Insufficient balance" })
      }
      const receiverAccount = await Account.findOne({ userId: parsedData.data.to }).session(session)
      if (!receiverAccount) {
        session.abortTransaction()
        res.status(400).json({ message: "Invalid account" })
      }

      await Account.updateOne({ userId: req.userId }, { $inc: { balance: -parsedData.data.amount } }).session(session)
      await Account.updateOne({ userId: parsedData.data.to }, { $inc: { balance: parsedData.data.amount } }).session(session)

      await session.commitTransaction();
      res.json({ message: 'Transfer successful' })
    } catch (err) {
      res.json({ Error: err })
    }
  })

module.exports = router