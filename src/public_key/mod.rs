use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Error, ErrorKind},
    sync::Mutex,
    vec::Vec,
};

use cosmian_crypto_base::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    entropy::CsRng,
    symmetric_crypto::{Key, SymmetricCrypto},
};
use rand_core::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    error::FormatErr,
    gpsw::{AbeScheme, AsBytes},
    msp::MonotoneSpanProgram,
};

pub type AbePrivateKey<T> = <T as AbeScheme>::UserDecryptionKey;

#[derive(Debug, Clone, PartialEq)]
pub struct AbePublicKey<T: AbeScheme + PartialEq + Clone>(pub T::MasterPublicKey);

impl<T: AbeScheme + Clone + PartialEq> TryFrom<&[u8]> for AbePublicKey<T> {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(AbePublicKey(
            T::MasterPublicKey::from_bytes(value)
                .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{}", e)))?,
        ))
    }
}

impl<T: AbeScheme + Clone + PartialEq> Display for AbePublicKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(bytes) = self.0.as_bytes() {
            write!(f, "{}", hex::encode(bytes))
        } else {
            write!(f, "Invalid input")
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbeKeyPair<T: AbeScheme + Clone + PartialEq>
where
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    private_key: AbePrivateKey<T>,
    public_key: AbePublicKey<T>,
}

impl<T: AbeScheme + Clone + PartialEq> KeyPair for AbeKeyPair<T>
where
    AbeKeyPair<T>: PartialEq + Clone,
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    type PrivateKey = AbePrivateKey<T>;
    type PublicKey = AbePublicKey<T>;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.private_key
    }
}

impl<T: AbeScheme + Clone + PartialEq> TryFrom<&[u8]> for AbeKeyPair<T>
where
    AbeKeyPair<T>: PartialEq + Clone,
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    type Error = std::io::Error;

    // this impl is based on `Display` impl below (keys are concatenated)
    // please keep the same order !
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let public_key = T::MasterPublicKey::from_bytes(value)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{}", e)))?;
        let private_key = AbePrivateKey::<T>::from_bytes(&value[public_key.len_bytes()..])
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{}", e)))?;
        Ok(AbeKeyPair {
            private_key,
            public_key: AbePublicKey(public_key),
        })
    }
}

impl<T: AbeScheme + Clone + PartialEq> AsBytes for AbeKeyPair<T>
where
    AbeKeyPair<T>: PartialEq + Clone,
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut bytes = self
            .public_key()
            .0
            .as_bytes()
            .map_err(|_e| FormatErr::ConversionFailed)?;
        bytes.extend(
            self.private_key()
                .as_bytes()
                .map_err(|_e| FormatErr::ConversionFailed)?,
        );
        Ok(bytes)
    }

    fn len_bytes(&self) -> usize {
        match self.as_bytes() {
            Ok(bytes) => bytes.len(),
            Err(_e) => 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let public_key = T::MasterPublicKey::from_bytes(bytes)
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        let private_key = AbePrivateKey::<T>::from_bytes(&bytes[public_key.len_bytes()..])
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        Ok(AbeKeyPair {
            private_key,
            public_key: AbePublicKey(public_key),
        })
    }
}

impl<T: AbeScheme + Clone + PartialEq> Display for AbeKeyPair<T>
where
    AbeKeyPair<T>: PartialEq + Clone,
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Ok(public_key), Ok(private_key)) =
            (self.public_key.0.as_bytes(), self.private_key.as_bytes())
        {
            write!(f, "{}{}", hex::encode(public_key), hex::encode(private_key))
        } else {
            write!(f, "Invalid data")
        }
    }
}

#[derive(Debug)]
pub struct AbeMasterPrivateKey<T: AbeScheme + Clone + PartialEq> {
    pub master_private_key: <T as AbeScheme>::MasterPrivateKey,
}

impl<T: AbeScheme + Clone + PartialEq> AsBytes for AbeMasterPrivateKey<T> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        self.master_private_key
            .as_bytes()
            .map_err(|_e| FormatErr::ConversionFailed)
    }

    fn len_bytes(&self) -> usize {
        match self.as_bytes() {
            Ok(bytes) => bytes.len(),
            Err(_e) => 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let master_private_key = T::MasterPrivateKey::from_bytes(bytes)
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        Ok(AbeMasterPrivateKey { master_private_key })
    }
}

#[derive(Debug)]
pub struct AbeMasterKey<T: AbeScheme + Clone + PartialEq> {
    pub master_private_key: <T as AbeScheme>::MasterPrivateKey,
    pub master_public_key: <T as AbeScheme>::MasterPublicKey,
    pub master_public_delegation_key: <T as AbeScheme>::MasterPublicDelegationKey,
}

impl<T: AbeScheme + Clone + PartialEq> Display for AbeMasterKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Ok(master_private_key), Ok(master_public_key), Ok(master_public_delegation_key)) = (
            self.master_private_key.as_bytes(),
            self.master_public_key.as_bytes(),
            self.master_public_delegation_key.as_bytes(),
        ) {
            write!(
                f,
                "{}{}{}",
                hex::encode(master_private_key),
                hex::encode(master_public_key),
                hex::encode(master_public_delegation_key)
            )
        } else {
            write!(f, "Invalid data")
        }
    }
}

impl<T: AbeScheme + Clone + PartialEq> AbeMasterKey<T> {
    pub fn new(nb_attributes: usize) -> anyhow::Result<Self> {
        let (master_private_key, master_public_key, master_public_delegation_key) =
            T::default().generate_master_key(nb_attributes)?;
        Ok(Self {
            master_private_key,
            master_public_key,
            master_public_delegation_key,
        })
    }
}

impl<T: AbeScheme + Clone + PartialEq> PartialEq for AbeMasterKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.master_private_key == other.master_private_key
            && self.master_public_key == other.master_public_key
            && self.master_public_delegation_key == other.master_public_delegation_key
    }
}

impl<T: AbeScheme + Clone + PartialEq> AsBytes for AbeMasterKey<T> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut bytes = self.master_private_key.as_bytes()?;
        bytes.extend(
            self.master_public_key
                .as_bytes()
                .map_err(|_e| FormatErr::ConversionFailed)?,
        );
        bytes.extend(
            self.master_public_delegation_key
                .as_bytes()
                .map_err(|_e| FormatErr::ConversionFailed)?,
        );
        Ok(bytes)
    }

    fn len_bytes(&self) -> usize {
        let bytes = self.as_bytes();
        match bytes {
            Ok(bytes) => bytes.len(),
            Err(_e) => 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let master_private_key = T::MasterPrivateKey::from_bytes(bytes)
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        let master_public_key =
            T::MasterPublicKey::from_bytes(&bytes[master_private_key.len_bytes()..])
                .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        let master_public_delegation_key = T::MasterPublicDelegationKey::from_bytes(
            &bytes[master_private_key.len_bytes() + master_public_key.len_bytes()..],
        )
        .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        Ok(AbeMasterKey {
            master_private_key,
            master_public_key,
            master_public_delegation_key,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct AbeCrypto<T: AbeScheme + Clone + PartialEq> {
    scheme: T,
    attrs: Option<Vec<u32>>,
}

impl<T: AbeScheme + Clone + PartialEq> AbeCrypto<T>
where
    AbeKeyPair<T>: PartialEq + Clone,
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    pub fn generate_key_pair(
        policy: &str,
        master_priv_key: &<T as AbeScheme>::MasterPrivateKey,
        master_pub_key: &<T as AbeScheme>::MasterPublicKey,
    ) -> anyhow::Result<AbeKeyPair<T>> {
        // warning: in this case, the encryption key is the 'public key'
        // and the decryption key is the 'private key'
        let user_decryption_key = T::default()
            .key_generation(&MonotoneSpanProgram::<i32>::parse(policy)?, master_priv_key)?;
        Ok(AbeKeyPair {
            public_key: AbePublicKey(master_pub_key.clone()),
            private_key: user_decryption_key,
        })
    }

    pub fn decrypt_symmetric_key_with_decryption_key<S: SymmetricCrypto>(
        &self,
        decryption_key: &AbePrivateKey<T>,
        data: &[u8],
    ) -> anyhow::Result<S::Key> {
        let decrypted = self.decrypt_with_decryption_key::<S>(decryption_key, data)?;
        let hasher = Shake256::default();
        let symkey = hasher
            .chain(&decrypted)
            .finalize_xof()
            .read_boxed(S::Key::LENGTH)
            .into_vec();
        S::Key::parse(symkey)
    }

    fn decrypt_with_decryption_key<S: SymmetricCrypto>(
        &self,
        decryption_key: &<T as AbeScheme>::UserDecryptionKey,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        self.scheme
            .decrypt(&T::CipherText::from_bytes(data)?, decryption_key)?
            .ok_or_else(|| anyhow::anyhow!("Invalid decryption"))?
            .as_bytes()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}

impl<T: AbeScheme + Clone + PartialEq> AsymmetricCrypto for AbeCrypto<T>
where
    AbeCrypto<T>: Sync,
    AbeCrypto<T>: Send,
    AbeKeyPair<T>: PartialEq + Clone,
    AbePrivateKey<T>: PartialEq + Clone,
    AbePublicKey<T>: PartialEq + Clone,
{
    type KeyPair = AbeKeyPair<T>;
    type KeygenParam = (usize, String);

    fn new() -> Self {
        panic!("ABE scheme must be initialized with attributes.")
    }

    #[must_use]
    fn new_attrs(attrs: &[u32]) -> Self {
        Self {
            scheme: T::default(),
            attrs: Some(attrs.to_vec()),
        }
    }

    fn description(&self) -> String {
        format!("Abe {}", T::description())
    }

    fn generate_key_pair(&self, param: Self::KeygenParam) -> anyhow::Result<Self::KeyPair> {
        // warning: in this case, the encryption key is the 'public key'
        // and the decryption key is the 'private key'
        let (master_priv_key, master_pub_key, _) = T::default().generate_master_key(param.0)?;
        let user_decryption_key = T::default().key_generation(
            &MonotoneSpanProgram::<i32>::parse(&param.1)?,
            &master_priv_key,
        )?;
        Ok(Self::KeyPair {
            public_key: AbePublicKey(master_pub_key),
            private_key: user_decryption_key,
        })
    }

    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        let rng = Mutex::new(CsRng::new());
        let rng = &mut *rng.lock().expect("a mutex lock failed");
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> anyhow::Result<(S::Key, Vec<u8>)> {
        let random_plain = self.scheme.generate_random_plaintext()?;
        let attrs = &self
            .attrs
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No attribute found for ABE scheme encryption"))?[..];
        let ciphertext = self.scheme.encrypt(&random_plain, attrs, &public_key.0)?;
        let hasher = Shake256::default();
        let symkey = hasher
            .chain(&random_plain.as_bytes()?)
            .finalize_xof()
            .read_boxed(S::Key::LENGTH)
            .into_vec();
        Ok((S::generate_key_from_rnd(&symkey)?, ciphertext.as_bytes()?))
    }

    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> anyhow::Result<S::Key> {
        let decrypted = self.decrypt(private_key, data)?;
        let hasher = Shake256::default();
        let symkey = hasher
            .chain(&decrypted)
            .finalize_xof()
            .read_boxed(S::Key::LENGTH)
            .into_vec();
        S::Key::parse(symkey)
    }

    fn encrypted_message_length(&self, _clear_text_message_length: usize) -> usize {
        match self.attrs.clone() {
            Some(attrs) => T::ciphertext_len(attrs.len()) as usize,
            None => 0,
        }
    }

    fn encrypt(&self, public_key: &AbePublicKey<T>, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let local_attrs = self
            .attrs
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No attribute found for ABE scheme encryption"))?;
        self.scheme
            .encrypt(
                &T::PlainText::from_bytes(data)?,
                &local_attrs[..],
                &public_key.0,
            )?
            .as_bytes()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn decrypt(&self, private_key: &AbePrivateKey<T>, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.scheme
            .decrypt(&T::CipherText::from_bytes(data)?, private_key)?
            .ok_or_else(|| anyhow::anyhow!("Invalid decryption"))?
            .as_bytes()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn clear_text_message_length(_encrypted_message_length: usize) -> usize {
        unimplemented!()
        // TODO: fixme, check and test this
        // It doesn't seem to be used at all,
        // but maybe it should be the size of deserialized Gt element
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use cosmian_crypto_base::symmetric_crypto::aes_256_gcm_pure;

    use super::{AbeKeyPair, AbeMasterKey, AbePrivateKey, AbePublicKey, AsymmetricCrypto, KeyPair};
    use crate::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{abe::Gpsw, AsBytes},
    };

    #[test]
    fn test_generate_key_pair_abe() {
        let param = (100, "1 & (4 | (2 & 3))".to_owned());
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let key_pair_1 = crypto.generate_key_pair(param.clone()).unwrap();
        assert!(
            !key_pair_1
                .private_key
                .as_bytes()
                .unwrap()
                .iter()
                .all(|&b| b == 0_u8)
        );
        assert!(
            !key_pair_1
                .public_key
                .0
                .as_bytes()
                .unwrap()
                .iter()
                .all(|&b| b == 0_u8)
        );

        let size = key_pair_1.private_key.as_bytes().unwrap().len();
        assert_eq!(size, 796);
        // TODO: can we get any constant private_key size somewhere?
        // assert_eq!(
        //     super::PRIVATE_KEY_LENGTH as usize,
        //     key_pair_1.private_key.as_bytes().unwrap().len()
        // );
        // TODO: fix `clear_text_message_length` fn to enable this test
        // assert_eq!(
        //     super::PUBLIC_KEY_LENGTH as usize,
        //     key_pair_1.public_key.v.len()
        // );
        let key_pair_2 = crypto.generate_key_pair(param).unwrap();
        assert_ne!(key_pair_2.private_key, key_pair_1.private_key);
        assert_ne!(key_pair_2.public_key.0, key_pair_1.public_key.0);
    }

    #[test]
    fn test_parse_key_pair() {
        let param = (100, "1 & (4 | (2 & 3))".to_owned());
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let key_pair = crypto.generate_key_pair(param).unwrap();

        let public_key_raw = key_pair.public_key.0.as_bytes().unwrap();
        let private_key_raw = key_pair.private_key.as_bytes().unwrap();

        let public = AbePublicKey::<Gpsw<Bls12_381>>::try_from(&public_key_raw[..]).unwrap();
        let private = AbePrivateKey::<Gpsw<Bls12_381>>::from_bytes(&private_key_raw[..]).unwrap();

        assert_eq!(key_pair.public_key(), &public);
        assert_eq!(key_pair.private_key(), &private);

        let mut bytes = vec![];
        bytes.extend(key_pair.public_key.0.as_bytes().unwrap());
        bytes.extend(key_pair.private_key.as_bytes().unwrap());
        let recovered = AbeKeyPair::<Gpsw<Bls12_381>>::try_from(&bytes[..]).unwrap();
        assert!(key_pair == recovered);

        let hex = format!("{}", key_pair);
        let my_hex = &hex::decode(hex).unwrap()[..];
        let recovered = AbeKeyPair::<Gpsw<Bls12_381>>::try_from(my_hex).unwrap();
        assert!(key_pair == recovered);
    }

    #[test]
    fn test_parse_public_key() {
        let param = (100, "1 & (4 | (2 & 3))".to_owned());
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let key_pair = crypto.generate_key_pair(param).unwrap();
        let hex = format!("{}", key_pair.public_key());
        let my_hex = &hex::decode(hex).unwrap()[..];
        let recovered = AbePublicKey::<Gpsw<Bls12_381>>::try_from(my_hex).unwrap();
        assert!(key_pair.public_key() == &recovered);
    }

    #[test]
    fn test_parse_private_key() {
        let param = (100, "1 & (4 | (2 & 3))".to_owned());
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let key_pair = crypto.generate_key_pair(param).unwrap();
        let hex = format!("{}", key_pair.private_key());
        let my_hex = &hex::decode(hex).unwrap()[..];
        let recovered = AbePrivateKey::<Gpsw<Bls12_381>>::from_bytes(my_hex).unwrap();
        assert!(key_pair.private_key() == &recovered);
    }

    #[test]
    fn test_encryption_decryption() {
        let param = (100, "1 & (4 | (2 & 3))".to_owned());
        let param2 = (100, "1 & (4 | (2 & 3))".to_owned());
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let key_pair = crypto.generate_key_pair(param).unwrap();
        // This is a complete whole different key pair, generated with another master
        // key
        let key_pair2 = crypto.generate_key_pair(param2).unwrap();

        let message = [0_u8; 32];
        let encoded_message = crypto.scheme.msg_encode(&message).unwrap().to_compressed();
        // let msg = encoded_message.to_compressed();
        let ciphered = crypto
            .encrypt(&key_pair.public_key, &encoded_message)
            .unwrap();
        let cleared = crypto.decrypt(&key_pair.private_key, &ciphered).unwrap();
        let cleared2 = crypto.decrypt(&key_pair2.private_key, &ciphered).unwrap();

        assert_eq!(cleared, encoded_message);
        assert_ne!(cleared2, encoded_message);
    }

    #[test]
    fn test_encryption_decryption_symmetric_key() {
        let param = (100, "1 & (4 | (2 & 3))".to_owned());
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);
        let key_pair = crypto.generate_key_pair(param).unwrap();

        let sym_key = crypto
            .generate_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(key_pair.public_key())
            .unwrap();
        let encrypted = sym_key.1;
        let decrypted_key = crypto.decrypt_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
            &key_pair.private_key,
            &encrypted,
        );
        println!("decrypted_key: {:?}", decrypted_key);
        assert_eq!(sym_key.0, decrypted_key.unwrap());
    }

    #[test]
    #[should_panic]
    fn test_encryption_decryption_symmetric_key_2_keypair() {
        let policy = "1 & (4 | (2 & 3))";
        let policy2 = "1 & (4 | (2 & 3))";
        let policy3 = "1 & 5";
        let crypto = super::AbeCrypto::<Gpsw<Bls12_381>>::new_attrs(&[1, 2, 3, 4]);

        let mk = AbeMasterKey::<Gpsw<Bls12_381>>::new(100).unwrap();

        let kp = super::AbeCrypto::<Gpsw<Bls12_381>>::generate_key_pair(
            policy,
            &mk.master_private_key,
            &mk.master_public_key,
        )
        .unwrap();
        let kp2 = super::AbeCrypto::<Gpsw<Bls12_381>>::generate_key_pair(
            policy2,
            &mk.master_private_key,
            &mk.master_public_key,
        )
        .unwrap();
        let kp3 = super::AbeCrypto::<Gpsw<Bls12_381>>::generate_key_pair(
            policy3,
            &mk.master_private_key,
            &mk.master_public_key,
        )
        .unwrap();

        assert_ne!(kp, kp2);
        assert_ne!(kp, kp3);
        assert_ne!(kp2, kp3);

        let sym_key = crypto
            .generate_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(kp.public_key())
            .unwrap();
        let encrypted = sym_key.1;
        let decrypted_key = crypto
            .decrypt_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(&kp.private_key, &encrypted)
            .unwrap();
        println!("decrypted_key: {:?}", decrypted_key);
        assert_eq!(sym_key.0, decrypted_key);

        let decrypted_key2 = crypto
            .decrypt_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
                &kp2.private_key,
                &encrypted,
            )
            .unwrap();
        println!("decrypted_key2: {:?}", decrypted_key2);
        assert_eq!(sym_key.0, decrypted_key2);

        let decrypted_key3 = crypto
            .decrypt_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
                &kp3.private_key,
                &encrypted,
            )
            .unwrap();
        println!("decrypted_key3: {:?}", decrypted_key3);
        assert_ne!(sym_key.0, decrypted_key3);
    }

    #[test]
    fn test_master_as_bytes() -> anyhow::Result<()> {
        let mk = AbeMasterKey::<Gpsw<Bls12_381>>::new(10)?;
        let bytes = mk.as_bytes()?;
        let mk2 = AbeMasterKey::<Gpsw<Bls12_381>>::from_bytes(&bytes[..])?;

        assert_eq!(mk, mk2);
        Ok(())
    }

    #[test]
    fn test_master_as_hex() -> anyhow::Result<()> {
        let mk = AbeMasterKey::<Gpsw<Bls12_381>>::new(10)?;
        let serialized_mk = format!("{}", mk);
        let hex = hex::decode(serialized_mk)?;
        let mk2 = AbeMasterKey::<Gpsw<Bls12_381>>::from_bytes(&hex[..])?;

        assert_eq!(mk, mk2);
        Ok(())
    }
}
