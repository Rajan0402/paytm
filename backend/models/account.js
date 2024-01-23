const mongoose = require('mongoose')
const zod = require('zod')

const AccountSchema = new mongoose.Schema({
  userId: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  }],
  balance: {
    type: Float64Array,
    required: true
  },
})

const transferBody = zod.object({
  to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  amount: {
    type: Float64Array,
    required: true
  }
})

const Account = mongoose.model('Account', AccountSchema)

module.exports = { Account, transferBody }