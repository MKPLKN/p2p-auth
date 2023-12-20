const os = require('os')
const fs = require('fs')
const path = require('path')

let cachedConfig = null

// Get the user's home directory
const homeDir = os.homedir()

let defaultConfig = {
  usersLocation: path.join(homeDir, '.p2p-auth')
}

function setConfig (key, value) {
  if (typeof key === 'object') {
    defaultConfig = { ...defaultConfig, ...key }
  } else {
    defaultConfig[key] = value
  }

  return defaultConfig
}

const loadConfigs = () => {
  // Read JSON config file
  const configPath = path.join(process.cwd(), 'p2p-auth-config.json')
  let configData = defaultConfig

  if (fs.existsSync(configPath)) {
    const rawConfigData = fs.readFileSync(configPath, 'utf8')
    configData = {
      ...defaultConfig,
      ...JSON.parse(rawConfigData)
    }
  }

  cachedConfig = {
    ...configData
  }

  return cachedConfig
}

// Getter function
const getConfig = (key = null, defaultValue = null) => {
  if (cachedConfig === null) {
    loadConfigs()
  }

  if (key === null) {
    return cachedConfig
  }

  return Object.prototype.hasOwnProperty.call(cachedConfig, key) ? cachedConfig[key] : defaultValue
}

module.exports = { getConfig, setConfig }
