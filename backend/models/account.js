const mongoose = require('mongoose')
const zod = require('zod')

const AccountSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  balance: {
    type: Number,
    required: true
  },
})

const transferBody = zod.object({
  to: zod.string(),
  amount: zod.number()
})

const Account = mongoose.model('Account', AccountSchema)

module.exports = { Account, transferBody }