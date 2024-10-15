use super::check_path;
use super::friends::Friend;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

/// You can have more than a single profile in the configuration file
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Profiles {
    #[serde(skip)]
    file_name: Option<String>,
    pub profiles: HashMap<String, Profile>,
}

/// Profile contains all the required information to run the various examples
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub mediator_did: String,
    pub ssl_certificate: Option<String>,
    pub network_address: String,
    pub friends: HashMap<String, Friend>,
}

pub const PROFILES_PATH: &str = "affinidi-messaging-helpers/conf/profiles.json";

impl Profiles {
    /// Loads profile config using Environment or command line argument
    /// priority is given in the following order
    /// 1. Command Line Argument
    /// 2. Environment Variable
    /// 3. First Profile in the file
    /// 4. Return Error if nothing found
    pub fn smart_load(
        args_profile: Option<String>,
        env_profile: Option<String>,
    ) -> Result<(String, Profile), Box<dyn Error>> {
        check_path()?;
        let profiles = Profiles::load_file(PROFILES_PATH)?;
        if let Some(args) = args_profile {
            if let Some(profile) = profiles.profiles.get(&args) {
                Ok((args, profile.clone()))
            } else {
                Err(format!("Couldn't find profile ({})!", args).into())
            }
        } else if let Some(env) = env_profile {
            if let Some(profile) = profiles.profiles.get(&env) {
                Ok((env, profile.clone()))
            } else {
                Err(format!("Couldn't find profile ({})!", env).into())
            }
        } else if profiles.profiles.is_empty() {
            Err("No profiles found!".into())
        } else if let Some((name, profile)) = profiles.profiles.iter().next() {
            Ok((name.to_string(), profile.clone()))
        } else {
            Err("No profiles found!".into())
        }
    }

    // Load saved profiles from file
    pub fn load_file(path: &str) -> Result<Self, Box<dyn Error>> {
        match Path::new(path).try_exists() {
            Ok(exists) => {
                if exists {
                    let file = File::open(path)?;
                    let reader = BufReader::new(file);
                    let mut profiles: Profiles = serde_json::from_reader(reader)?;
                    profiles.file_name = Some(path.to_string());
                    Ok(profiles)
                } else {
                    Ok(Profiles {
                        file_name: Some(path.to_string()),
                        ..Default::default()
                    })
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    // Saves profiles to a file
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let contents = serde_json::to_string_pretty(self)?;
        let mut f = File::create(self.file_name.as_ref().unwrap())?;
        f.write_all(contents.as_bytes())?;
        Ok(())
    }

    // Adds a new profile
    pub fn add(&mut self, name: &str, profile: Profile) -> bool {
        self.profiles.insert(name.to_string(), profile).is_none()
    }

    // Removes a profile
    pub fn remove(&mut self, name: &str) -> bool {
        self.profiles.remove(name).is_some()
    }
}
