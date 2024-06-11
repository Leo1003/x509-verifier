use std::time::SystemTime;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// If this field is set to `None`, the verify time is
    /// at the moment when the certificate got verified.
    verify_time: Option<OffsetDateTime>,

    bypass_validity_check: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            verify_time: None,
            bypass_validity_check: false,
        }
    }
}

impl VerifyOptions {
    /// Get the verify time which is used to verify the validity of certificates
    pub fn verify_time(&self) -> OffsetDateTime {
        self.verify_time.unwrap_or_else(OffsetDateTime::now_utc)
    }

    /// Set the verify time to the current time.
    /// this is the default value of the options.
    pub fn set_verify_time_now(&mut self) -> &mut Self {
        self.verify_time = None;
        self
    }

    /// Set the verify time using `time::OffsetDateTime`
    pub fn set_verify_time(&mut self, time: OffsetDateTime) -> &mut Self {
        self.verify_time = Some(time);
        self
    }

    /// Set the verify time using `std::time::SystemTime`
    pub fn set_verify_time_std(&mut self, time: SystemTime) -> &mut Self {
        self.verify_time = Some(time.into());
        self
    }

    pub fn insecure_bypass_validity_check(&self) -> bool {
        self.bypass_validity_check
    }

    /// Make the verifier bypass the time check.
    ///
    /// This is useful to let user choose to only ignore the expiration issues
    /// instead of bypass all the other checks.
    ///
    /// Not recommend to set this to true without user's agreement.
    pub fn set_insecure_bypass_validity_check(&mut self, bypass: bool) -> &mut Self {
        self.bypass_validity_check = bypass;
        self
    }
}
