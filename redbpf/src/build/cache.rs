#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use serde_json;

use ring::digest;

#[derive(Serialize, Deserialize)]
pub struct BuildCache(HashMap<String, Vec<u8>>, PathBuf);

impl BuildCache {
   pub  fn new(dir: &Path) -> BuildCache {
        let file = dir.join(".build_manifest");
        let cache = match File::open(&file)
            .map_err(serde_json::Error::io)
            .and_then(serde_json::from_reader)
        {
            Ok(cache) => cache,
            Err(_) => HashMap::new(),
        };

        println!("{:?}", cache);
        BuildCache(cache, file)
    }

    /// Error conditions will return true
    pub fn file_changed(&mut self, file: &Path) -> bool {
        let fname = match file.to_str() {
            Some(n) => n,
            None => return true
        }.to_string();
        let entry = self.0.entry(fname).or_default();

        let digest = match fs::read(file) {
            Ok(content) => digest::digest(&digest::SHA256, content.as_slice()),
            Err(_) => return true
        };

        let is_match = digest.as_ref() == entry.as_slice();
        *entry = digest.as_ref().to_vec();

        !is_match
    }

    pub fn save(&self) {
        serde_json::to_writer(File::create(&self.1).unwrap(), &self.0).unwrap();
    }
}

