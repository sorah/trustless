use secrecy::SecretBox;

/// A byte buffer that serializes as base64 on the wire.
///
/// Implements [`zeroize::Zeroize`], [`secrecy::SerializableSecret`], and
/// [`secrecy::CloneableSecret`] so it can be used inside [`SecretBox`] with
/// full serde and Clone support.
#[serde_with::serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Base64Bytes(
    #[serde_as(
        as = "serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>"
    )]
    Vec<u8>,
);

impl zeroize::Zeroize for Base64Bytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl secrecy::SerializableSecret for Base64Bytes {}
impl secrecy::CloneableSecret for Base64Bytes {}

impl std::ops::Deref for Base64Bytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Base64Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Base64Bytes {
    /// Wrap into a `SecretBox`.
    pub fn into_secret(self) -> SecretBox<Base64Bytes> {
        Box::new(self).into()
    }
}
