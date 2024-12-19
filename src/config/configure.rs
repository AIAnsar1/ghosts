use std::fs;
use self::super::base::{Config};



impl Config {
    pub fn from_string(toml: &str) -> Result<Config, Error> {
        let config: Config = match toml::from_str(toml) {
            Ok(config) => config,
            Err(e) => bail!("[ ERROR ]: Parse In The Configuration File: {}", e),
        };
        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Config, Error> {
        let toml = fs::read_to_string(path)?;
        Config::from_string(&toml)
    }
}