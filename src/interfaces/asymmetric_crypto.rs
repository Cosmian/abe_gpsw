use std::{convert::TryFrom, sync::Mutex};

use cosmian_crypto_base::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    entropy::CsRng,
    hybrid_crypto::{BytesScanner, Header, Metadata},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Key, Nonce, SymmetricCrypto},
};
use rand_core::RngCore;

use crate::{
    core::{gpsw::AbeScheme, Engine},
    interfaces::policy::{AccessPolicy, Attribute, Policy},
};

#[derive(Clone, PartialEq)]
pub struct AbeMasterKeys<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    pub master_private_key: S::MasterPrivateKey,
    pub public_key: S::MasterPublicKey,
    pub master_public_delegation_key: S::MasterPublicDelegationKey,
}

#[derive(Clone, PartialEq)]
pub struct AbeKeyPair<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    pub public_key: S::MasterPublicKey,
    pub private_key: S::UserDecryptionKey,
}

impl<S> KeyPair for AbeKeyPair<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    type PrivateKey = S::UserDecryptionKey;
    type PublicKey = S::MasterPublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.private_key
    }
}

pub struct PrivateKeyGenerationParameters<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    pub master_private_key: S::MasterPrivateKey,
    pub policy: Policy,
    pub access_policy: AccessPolicy,
}

pub struct KeyPairGenerationParameters<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    pub master_private_key: S::MasterPrivateKey,
    pub policy: Policy,
    pub master_public_key: S::MasterPublicKey,
    pub access_policy: AccessPolicy,
}

pub struct EncryptionParameters {
    pub policy: Policy,
    pub policy_attributes: Vec<Attribute>,
}

pub struct AbeCrypto<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    rng: Mutex<CsRng>,
    engine: Engine<S>,
}

impl<S> Default for AbeCrypto<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> AbeCrypto<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    /// Generate an ABE master key pair for the Policy, returning a triple
    /// (private key, public key, public delegation key)
    #[cfg(test)]
    fn generate_master_keys(&self, policy: &Policy) -> anyhow::Result<AbeMasterKeys<S>> {
        let (msk, pk, mdk) = self
            .engine
            .generate_master_key(policy)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(AbeMasterKeys {
            master_private_key: msk,
            public_key: pk,
            master_public_delegation_key: mdk,
        })
    }
}

/// Implementation of the AsymmetricCrypto trait for a user:
/// the Public Key is identical to the Master Public Key, while the Private Key
/// is a User Decryption Key
impl<S> AsymmetricCrypto for AbeCrypto<S>
where
    S: AbeScheme + std::marker::Sync + std::marker::Send,
{
    type EncryptionParameters = EncryptionParameters;
    type KeyPair = AbeKeyPair<S>;
    type KeyPairGenerationParameters = KeyPairGenerationParameters<S>;
    type PrivateKeyGenerationParameters = PrivateKeyGenerationParameters<S>;

    fn new() -> Self {
        AbeCrypto {
            rng: Mutex::new(CsRng::new()),
            engine: Engine::<S>::new(),
        }
    }

    fn description(&self) -> String {
        "The GPSW KP-ABE over BLS12-381 encryption scheme for an user".to_string()
    }

    fn generate_private_key(
        &self,
        parameters: Option<&Self::PrivateKeyGenerationParameters>,
    ) -> anyhow::Result<<Self::KeyPair as KeyPair>::PrivateKey> {
        let parameters = parameters.ok_or_else(|| {
            anyhow::anyhow!("The private key generation parameters are mandatory")
        })?;
        let private_key = self.engine.generate_user_key(
            &parameters.policy,
            &parameters.master_private_key,
            &parameters.access_policy,
        )?;
        Ok(private_key)
    }

    fn generate_key_pair(
        &self,
        parameters: Option<&Self::KeyPairGenerationParameters>,
    ) -> anyhow::Result<Self::KeyPair> {
        let parameters = parameters
            .ok_or_else(|| anyhow::anyhow!("The key pair generation parameters are mandatory"))?;
        let private_key = self.engine.generate_user_key(
            &parameters.policy,
            &parameters.master_private_key,
            &parameters.access_policy,
        )?;
        Ok(AbeKeyPair {
            public_key: parameters.master_public_key.clone(),
            private_key,
        })
    }

    fn generate_symmetric_key<C: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        parameters: Option<&Self::EncryptionParameters>,
    ) -> anyhow::Result<(C::Key, Vec<u8>)> {
        let parameters = parameters.ok_or_else(|| {
            anyhow::anyhow!(
                "The Policy Attributes must be provided to generate a hybrid encryption symmetric \
                 key"
            )
        })?;
        let (sk_bytes, encrypted_sk) = self.engine.generate_symmetric_key(
            &parameters.policy,
            public_key,
            &parameters.policy_attributes,
            C::Key::LENGTH,
        )?;
        let sk = C::Key::parse(sk_bytes)?;
        Ok((sk, encrypted_sk))
    }

    fn decrypt_symmetric_key<C: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        encrypted_symmetric_key: &[u8],
    ) -> anyhow::Result<C::Key> {
        let sk_bytes = self.engine.decrypt_symmetric_key(
            private_key,
            encrypted_symmetric_key,
            C::Key::LENGTH,
        )?;
        C::Key::parse(sk_bytes)
    }

    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn encrypted_message_length(&self, _clear_text_message_length: usize) -> usize {
        0 //TODO
    }

    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        encryption_parameters: Option<&Self::EncryptionParameters>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let header = Header::<Self, Aes256GcmCrypto>::generate(
            public_key,
            encryption_parameters,
            Metadata {
                uid: vec![],
                additional_data: None,
            },
        )?;
        let header_bytes = header.as_bytes()?;
        let sym_crypto = Aes256GcmCrypto::new();
        let nonce = sym_crypto.generate_nonce();
        let encrypted_data = sym_crypto.encrypt(header.symmetric_key(), data, &nonce, None)?;
        let mut bytes: Vec<u8> = u32::try_from(header_bytes.len())
            .map_err(|_| anyhow::anyhow!("The header is too long"))?
            .to_be_bytes()
            .to_vec();
        bytes.extend(header_bytes);
        bytes.extend(nonce.as_bytes());
        bytes.extend(encrypted_data);
        Ok(bytes)
    }

    fn clear_text_message_length(_encrypted_message_length: usize) -> usize {
        0 //TODO
    }

    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        encrypted_data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut scanner = BytesScanner::new(encrypted_data);
        let header_len = scanner.read_u32()?;
        let header = Header::<Self, Aes256GcmCrypto>::from_bytes(
            scanner.next(header_len as usize)?,
            private_key,
        )?;
        let nonce = Nonce::try_from(
            scanner
                .next(<Aes256GcmCrypto as SymmetricCrypto>::Nonce::LENGTH)?
                .to_vec(),
        )?;
        let sym_crypto = Aes256GcmCrypto::new();
        match scanner.remainder() {
            Some(b) => sym_crypto.decrypt(header.symmetric_key(), b, &nonce, None),
            None => Ok(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_base::{
        asymmetric::AsymmetricCrypto, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    };

    use super::{AbeCrypto, PrivateKeyGenerationParameters};
    use crate::{
        core::{bilinear_map::bls12_381::Bls12_381, gpsw::Gpsw},
        interfaces::{
            asymmetric_crypto::EncryptionParameters,
            policy::{ap, attr, Attribute, Policy},
        },
    };

    #[test]
    pub fn test_symmetric_keys() -> anyhow::Result<()> {
        let policy = Policy::new(100)
            .add_axis(
                "Security Level",
                &[
                    "Protected",
                    "Low Secret",
                    "Medium Secret",
                    "High Secret",
                    "Top Secret",
                ],
                true,
            )?
            .add_axis("Department", &["R&D", "HR", "MKG", "FIN"], false)?;
        let abe = AbeCrypto::<Gpsw<Bls12_381>>::new();
        let master_keys = abe.generate_master_keys(&policy)?;

        let high_secret_fin_mkg_access_policy = ap("Security Level", "High Secret")
            & (ap("Department", "MKG") | ap("Department", "FIN"));
        let user_key = abe.generate_private_key(Some(&PrivateKeyGenerationParameters {
            master_private_key: master_keys.master_private_key,
            access_policy: high_secret_fin_mkg_access_policy,
            policy: policy.clone(),
        }))?;

        let attributes: Vec<Attribute> = vec![
            attr("Department", "FIN"),
            attr("Security Level", "Low Secret"),
        ];
        let (sym_key, enc_sym_key) = abe.generate_symmetric_key::<Aes256GcmCrypto>(
            &master_keys.public_key,
            Some(&EncryptionParameters {
                policy,
                policy_attributes: attributes,
            }),
        )?;

        let rec_sym_key = abe.decrypt_symmetric_key::<Aes256GcmCrypto>(&user_key, &enc_sym_key)?;

        assert_eq!(sym_key, rec_sym_key);

        Ok(())
    }

    #[test]
    pub fn test_encrypt_decrypt() -> anyhow::Result<()> {
        let policy = Policy::new(100)
            .add_axis(
                "Security Level",
                &[
                    "Protected",
                    "Low Secret",
                    "Medium Secret",
                    "High Secret",
                    "Top Secret",
                ],
                true,
            )?
            .add_axis("Department", &["R&D", "HR", "MKG", "FIN"], false)?;
        let abe = AbeCrypto::<Gpsw<Bls12_381>>::new();
        let master_keys = abe.generate_master_keys(&policy)?;

        let high_secret_fin_mkg_access_policy = ap("Security Level", "High Secret")
            & (ap("Department", "MKG") | ap("Department", "FIN"));
        let user_key = abe.generate_private_key(Some(&PrivateKeyGenerationParameters {
            master_private_key: master_keys.master_private_key,
            access_policy: high_secret_fin_mkg_access_policy,
            policy: policy.clone(),
        }))?;

        let message = abe.generate_random_bytes(42);
        let attributes: Vec<Attribute> = vec![
            attr("Department", "FIN"),
            attr("Security Level", "Low Secret"),
        ];
        let encrypted = abe.encrypt(
            &master_keys.public_key,
            Some(&EncryptionParameters {
                policy,
                policy_attributes: attributes,
            }),
            &message,
        )?;

        let decrypted = abe.decrypt(&user_key, &encrypted)?;

        assert_eq!(message, decrypted);

        Ok(())
    }
}
