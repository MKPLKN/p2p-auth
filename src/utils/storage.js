import fs from 'fs/promises'
import path from 'path'
import { getConfig } from './config.js'

export const USERS_LOCATION = getConfig('usersLocation')

function buildUserPath (username) {
  return `${USERS_LOCATION}/${username}.bin`
}

export async function getUsersList () {
  let files = []
  try {
    files = await fs.readdir(USERS_LOCATION)
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Directory does not exist, create it recursively
      await fs.mkdir(USERS_LOCATION, { recursive: true })
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

export async function retrieveEncryptedSeedAndSalt (username) {
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
      return {} // File not found, return empty object
    }
    throw error // Propagate other errors
  }
}

export async function storeEncryptedSeedAndSalt (username, encryptedSeedWithIVAndTag, saltBuffer) {
  // Ensure the storage directory exists
  await fs.mkdir(USERS_LOCATION, { recursive: true })

  // Construct the path for the user's file
  const filePath = buildUserPath(username)

  // Convert the entire string (IV + encrypted data + auth tag) and the salt to buffers
  const encryptedDataBuffer = Buffer.from(encryptedSeedWithIVAndTag, 'hex')

  // Combine the encrypted data buffer and the salt buffer
  const combinedBuffer = Buffer.concat([encryptedDataBuffer, saltBuffer])

  // Write the combined binary data to a file
  await fs.writeFile(filePath, combinedBuffer)
}
