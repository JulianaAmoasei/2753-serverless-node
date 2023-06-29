const { verify, sign } = require('jsonwebtoken')
const { buildResponse } = require('./utils')
const { pbkdf2Sync } = require('crypto')

function createToken(username, id) {
  const token = sign({ username, id }, process.env.JWT_SECRET, {
    expiresIn: '24h',
    audience: 'alura-serverless'
  })
  return token
}

async function authorize(event) {
  const { authorization } = event.headers
  if (!authorization) {
    return buildResponse(401, { error: 'Missing authorization header' })
  }

  const [type, token] = authorization.split(' ')
  if (type !== 'Bearer' || !token) {
    return buildResponse(401, { error: 'Invalid authorization header' })
  }
  
  const decodedToken = verify(token, process.env.JWT_SECRET, { audience: 'alura-serverless' })
  if (!decodedToken) {
    return buildResponse(401, { error: 'Invalid token' })
  }
    return decodedToken
}

function makeHash(password) {
  return pbkdf2Sync(password, process.env.SALT, 100000, 64, 'sha512').toString('hex')
}

module.exports = {
  authorize,
  createToken,
  makeHash
}