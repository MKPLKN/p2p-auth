import fs from 'fs'
import path from 'path'

let cachedConfig = null

// Helper function to get default config
export const getDefaultConfig = () => ({
  usersLocation: './.p2p-auth'
})

export const loadConfigs = () => {
  const defaultConfig = getDefaultConfig()

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
export const getConfig = (key = null, defaultValue = null) => {
  if (cachedConfig === null) {
    loadConfigs()
  }

  if (key === null) {
    return cachedConfig
  }

  return Object.prototype.hasOwnProperty.call(cachedConfig, key) ? cachedConfig[key] : defaultValue
}
