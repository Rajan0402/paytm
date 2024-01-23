const mongoose = require("mongoose")
const zod = require('zod')

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minLength: 3,
    maxLength: 30
  },
  password: {
    type: String,
    required: true,
    minLength: 6
  },
  firstname: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    maxLength: 30
  },
  lastname: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    maxLength: 30
  },
  refresh_token: String
})

const updateBody = zod.object({
  password: zod.string().min(6, { message: "Password must be at least 6 characters long." }).optional(),
  firstname: zod.string().optional(),
  lastname: zod.string().optional(),
})

const signUpBody = zod.object({
  username: zod.string().email(),
  password: zod.string().min(6, { message: "Password must be at least 6 characters long." }),
  firstname: zod.string().min(3, { message: "must be at least 3 characters long." }).max(30, { message: "must be less than 30 characters." }),
  lastname: zod.string().min(3, { message: "must be at least 3 characters long." }).max(30, { message: "must be less than 30 characters." }),
})

const signInBody = zod.object({
  username: zod.string().email(),
  password: zod.string()
})

const User = mongoose.model("User", UserSchema)

module.exports = { User, updateBody, signInBody, signUpBody }