use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub time: SystemTime,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            time: SystemTime::now(),
        }
    }
}
