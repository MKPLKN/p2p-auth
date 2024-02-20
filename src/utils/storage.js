const fs = require('fs/promises')
const path = require('path')
const { getConfig } = require('./config.js')
const { randomBytes } = require('crypto')

function buildUserPath (username) {
  return `${getConfig('usersLocation')}/${username}.bin`
}

async function getUsersList () {
  let files = []
  try {
    files = await fs.readdir(getConfig('usersLocation'))
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Directory does not exist, create it recursively
      await fs.mkdir(getConfig('usersLocation'), { recursive: true })
    } else {
      throw error
    }
  }

  const users = []
  for (const file of files) {
    if (file.endsWith('.bin')) {
      users.push(path.basename(file, '.bin'))
    }
  }

  return users
}

async function retrieveEncryptedSeedAndSalt (username) {
  const filePath = buildUserPath(username)

  try {
    const fileData = await fs.readFile(filePath)

    const iv = fileData.slice(0, 16)
    const saltStart = fileData.length - 64
    const encryptedSeed = fileData.slice(16, saltStart - 16)
    const authTag = fileData.slice(saltStart - 16, saltStart)
    const salt = fileData.slice(saltStart)

    return { iv, authTag, encryptedSeed, salt }
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { code: 404 } // File not found
    }
    throw error // Propagate other errors
  }
}

async function storeEncryptedSeedAndSalt (username, encryptedSeedWithIVAndTag, saltBuffer) {
  // Ensure the storage directory exists
  await fs.mkdir(getConfig('usersLocation'), { recursive: true })

  // Construct the path for the user's file
  const filePath = buildUserPath(username)

  // Convert the entire string (IV + encrypted data + auth tag) and the salt to buffers
  const encryptedDataBuffer = Buffer.from(encryptedSeedWithIVAndTag, 'hex')

  // Combine the encrypted data buffer and the salt buffer
  const combinedBuffer = Buffer.concat([encryptedDataBuffer, saltBuffer])

  // Write the combined binary data to a file
  await fs.writeFile(filePath, combinedBuffer)
}

async function retrieveNonceChiperAndSalt (username) {
  const filePath = buildUserPath(username)

  try {
    const fileData = await fs.readFile(filePath)

    const nonce = fileData.slice(0, 24)
    const ciphertext = fileData.slice(24, 24 + 48)
    const salt = fileData.slice(24 + 48, 24 + 48 + 16)

    return { nonce, ciphertext, salt }
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { code: 404 } // File not found
    }
    throw error // Propagate other errors
  }
}

async function storeNonceChiperAndSalt (username, nonceAndChiperAndSalt) {
  // Ensure the storage directory exists
  await fs.mkdir(getConfig('usersLocation'), { recursive: true })

  // Construct the path for the user's file
  const filePath = buildUserPath(username)

  // Combine the encrypted data buffer and the salt buffer
  const { nonce, ciphertext, salt } = nonceAndChiperAndSalt
  const combinedBuffer = Buffer.concat([nonce, ciphertext, salt])

  // Write the combined binary data to a file
  await fs.writeFile(filePath, combinedBuffer)
}

module.exports = {
  getUsersList,
  retrieveEncryptedSeedAndSalt,
  storeEncryptedSeedAndSalt,
  storeNonceChiperAndSalt,
  retrieveNonceChiperAndSalt
}
