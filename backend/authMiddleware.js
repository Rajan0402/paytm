const jwt = require('jsonwebtoken')

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization
  if (!authHeader?.startsWith("Bearer ")) return res.sendStatus(401);

  const token = authHeader.split(" ")[1]
  jwt.verify(token, process.env.ACCESS_JWT_SECRET, (err, decoded) => {
    if (err) res.status(403).json({ Error: err })
    req.userId = decoded.userId
    next()
  })
}

module.exports = authMiddleware