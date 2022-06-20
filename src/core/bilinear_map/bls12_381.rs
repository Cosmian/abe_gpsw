use core::ops::{Add, Deref, DerefMut, Div, Mul, Neg, Sub};
use std::convert::TryInto;

use cosmian_bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
};
use ff::Field;
use group::Group;
use rand::{CryptoRng, RngCore};

use super::BilinearMap;
use crate::{core::gpsw::AsBytes, error::FormatErr};

#[derive(Default, Debug, PartialEq, Clone)]
pub struct Bls12_381;

#[derive(Clone, Debug)]
pub struct Scalar(cosmian_bls12_381::Scalar);

impl Deref for Scalar {
    type Target = cosmian_bls12_381::Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Scalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> Add<&'a Scalar> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'a Scalar) -> Self {
        Scalar(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a Scalar> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'a Scalar) -> Self {
        Scalar(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'a Scalar) -> Self {
        Scalar(self.0 * rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> Div<&'a Scalar> for Scalar {
    type Output = Self;

    fn div(self, rhs: &'a Scalar) -> Self {
        let inv = rhs.invert().unwrap(); // Division by Zero;
        Scalar(self.0 * inv)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        Scalar(-self.0)
    }
}

impl From<i32> for Scalar {
    fn from(int: i32) -> Self {
        let scalar = cosmian_bls12_381::Scalar::from(int.abs() as u64);
        if int < 0 {
            Scalar(-scalar)
        } else {
            Scalar(scalar)
        }
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl AsBytes for Scalar {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        Ok(self.to_bytes().to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        if bytes.len() < 32 {
            return Err(FormatErr::InvalidSize(format!(
                "Invalid scalar element (size {}, expected size at least: {} bytes long), unable \
                 to deserialize this scalar element.",
                bytes.len(),
                32
            )));
        }

        let inner = cosmian_bls12_381::Scalar::from_bytes(bytes[0..32].try_into()?);
        if inner.is_some().into() {
            Ok(Scalar(inner.unwrap()))
        } else {
            Err(FormatErr::Deserialization(
                "Failed deserializing scalar".to_string(),
            ))
        }
    }

    fn len_bytes(&self) -> usize {
        32
    }
}

impl AsBytes for cosmian_bls12_381::G1Affine {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        Ok(self.to_compressed().to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        if bytes.len() < 48 {
            return Err(FormatErr::InvalidSize(format!(
                "Invalid G1 element (size {}, compressed expected size at least: {} bytes long), \
                 unable to deserialize this G1 element.",
                bytes.len(),
                48
            )));
        }
        let res = cosmian_bls12_381::G1Affine::from_compressed(&bytes[0..48].try_into()?);
        if res.is_none().into() {
            Err(FormatErr::Deserialization(
                "Error deserializing G1Affine".to_string(),
            ))
        } else {
            Ok(res.unwrap())
        }
    }

    fn len_bytes(&self) -> usize {
        48
    }
}

impl AsBytes for cosmian_bls12_381::G2Affine {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        Ok(self.to_compressed().to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        if bytes.len() < 96 {
            return Err(FormatErr::InvalidSize(format!(
                "Invalid G2 element (size {}, compressed expected size at least: {} bytes long), \
                 unable to deserialize this G2 element.",
                bytes.len(),
                96
            )));
        }
        let res = cosmian_bls12_381::G2Affine::from_compressed(&bytes[0..96].try_into()?);
        if res.is_none().into() {
            Err(FormatErr::Deserialization(
                "Error deserializing G2Affine".to_string(),
            ))
        } else {
            Ok(res.unwrap())
        }
    }

    fn len_bytes(&self) -> usize {
        96
    }
}

impl AsBytes for cosmian_bls12_381::Gt {
    // At the moment (july 2021), no serialization is available from bls12-381
    // library Gt-serialization has been added from existing PR: `Implemented
    // serialization of Fp2, Fp6, Fp12 and Gt` Thanks to Aurore Guillevic, Gt
    // deserialization includes 2 new verifications see crate BLS12_381,
    // function is_get_element
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        Ok(self.to_compressed().to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        if bytes.len() < 288 {
            return Err(FormatErr::InvalidSize(format!(
                "Invalid Gt element (size {}, compressed expected size at least: {} bytes long), \
                 unable to deserialize this Gt element.",
                bytes.len(),
                288
            )));
        }
        let res = cosmian_bls12_381::Gt::from_compressed(&bytes[0..288].try_into()?);
        if res.is_none().into() {
            Err(FormatErr::Deserialization(
                "Error deserializing Gt".to_string(),
            ))
        } else {
            Ok(res.unwrap())
        }
    }

    fn len_bytes(&self) -> usize {
        // A serialized element on Gt is 576 bytes long (because p has 381 bits, so an
        // element in Fp12 has 381*12 bits). The same compressed element is 288 bytes
        // long (288 = 381*12/8/2).
        288
    }
}

// bilinear map: G1 x G2 -> Gt
// note that BilinearMap trait use multiplicative notation whereas
// cosmian_bls12_381 is an additive group cosmian_bls12_381 allows pairing
// optimization using preprocessing in G2. For that purpose we swapped G1 and G2
// to use preprocessing during Key Generation instead of encryption To optimize
// the decryption, we set G1 to cosmian_bls12_381 G2Prepared
impl BilinearMap for Bls12_381 {
    type G1 = G2Prepared;
    type G2 = G1Affine;
    type G3 = G2Affine;
    type Gt = Gt;
    type Scalar = Scalar;

    const ONE: Scalar = Scalar(cosmian_bls12_381::Scalar::one());
    const ZERO: Scalar = Scalar(cosmian_bls12_381::Scalar::zero());

    fn description() -> String {
        "BLS12-381".to_string()
    }

    fn gen_rand_scalar_inner<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<Scalar, FormatErr> {
        Ok(Scalar(<cosmian_bls12_381::Scalar as Field>::random(rng)))
    }

    fn gen_rand_gt_inner<R: CryptoRng + RngCore>(&self, rng: &mut R) -> Result<Gt, FormatErr> {
        Ok(<cosmian_bls12_381::Gt as Group>::random(rng))
    }

    fn msg_to_scalar(&self, msg: &[u8]) -> Result<Scalar, FormatErr> {
        if msg.len() > 32 {
            return Err(FormatErr::InvalidSize("message too long".to_string()));
        }
        let mut vec = msg.to_vec();
        vec.resize(32, 0);
        let scl = cosmian_bls12_381::Scalar::from_bytes(&(vec.as_slice().try_into()?));
        if scl.is_none().into() {
            return Err(FormatErr::ConversionFailed);
        }
        Ok(Scalar(scl.unwrap()))
    }

    // compute g1^x
    fn g2_gen_exp(&self, x: &Scalar) -> G1Affine {
        G1Affine::from(G1Projective::generator() * x.0)
    }

    // compute g2^x
    fn g1_gen_exp(&self, x: &Scalar) -> (G2Prepared, G2Affine) {
        let res = G2Affine::from(G2Projective::generator() * x.0);
        (G2Prepared::from(res), res)
    }

    fn g3_gen_exp(&self, x: &Scalar) -> G2Affine {
        G2Affine::from(G2Projective::generator() * x.0)
    }

    // compute a x b where a and b \in G3
    fn g3_mul(&self, a: &G2Affine, b: &G2Affine) -> (G2Prepared, G2Affine) {
        let res = G2Affine::from(G2Projective::from(a) + b);
        (G2Prepared::from(res), res)
    }

    // compute a^x where a \in G3
    fn g3_exp(&self, a: &G2Affine, x: &Scalar) -> G2Affine {
        G2Affine::from(a * x.0)
    }

    // prepare (g2^x)
    fn g3_to_g1(x: &G2Affine) -> G2Prepared {
        G2Prepared::from(*x)
    }

    // compute e(g1,g2)^x
    fn gt_gen_exp(&self, x: &Scalar) -> Gt {
        <cosmian_bls12_381::Gt as Group>::generator() * x.0
    }

    // compute a^x where a \in G2
    fn g2_exp(&self, a: &G1Affine, x: &Scalar) -> G1Affine {
        G1Affine::from(a * x.0)
    }

    // compute a^x where a \in Gt
    fn gt_exp(&self, a: &Gt, x: &Scalar) -> Gt {
        a * x.0
    }

    // compute a x b where a and b \in Gt
    fn gt_mul(&self, a: &Gt, b: &Gt) -> Gt {
        a + b
    }

    // compute a x b where a and b \in Gt
    fn gt_div(&self, a: &Gt, b: &Gt) -> Gt {
        a - b
    }

    // compute Π e(d_i,e_i)^α_i where e is the pairing G1 x G2 -> Gt
    // In bls12-381 this computation can be speed up using MillerLoop
    fn prod_gt_exp(&self, d_i: &[&G2Prepared], e_i: &[&G1Affine], a_i: &[&Scalar]) -> Gt {
        //compute e_i^α_i
        let e_i_a_i = e_i
            .iter()
            .zip(a_i.iter())
            .map(|(ei, ai)| G1Affine::from((*ei) * ai.0))
            .collect::<Vec<_>>();
        // compute Π e(d_i,e_i^α_i)= Π e(d_i,e_i)^α_i
        let terms = e_i_a_i.iter().zip(d_i.iter().copied()).collect::<Vec<_>>();
        multi_miller_loop(&terms).final_exponentiation()
    }
}

#[cfg(test)]
mod tests {
    use cosmian_bls12_381::{G1Affine, G2Affine, Gt};

    use crate::{
        core::{
            bilinear_map::bls12_381::{BilinearMap, Bls12_381, Scalar},
            gpsw::AsBytes,
        },
        error::FormatErr,
    };

    #[test]
    fn scalar_as_bytes() -> Result<(), FormatErr> {
        let grp = Bls12_381;
        let scl = grp.gen_random_scalar()?;
        let scl_2 = Scalar::try_from_bytes(&scl.try_into_bytes()?)?;
        assert_eq!(scl, scl_2);
        Ok(())
    }

    #[test]
    fn g1_affine_as_bytes() -> Result<(), FormatErr> {
        let grp = Bls12_381;
        let g1 = grp.g2_gen_exp(&grp.gen_random_scalar()?);
        let g1_2 = G1Affine::try_from_bytes(&g1.try_into_bytes()?)?;
        assert_eq!(g1, g1_2);
        Ok(())
    }

    #[test]
    fn g2_affine_as_bytes() -> Result<(), FormatErr> {
        let grp = Bls12_381;
        let g2 = grp.g1_gen_exp(&grp.gen_random_scalar()?).1;
        let g2_2 = G2Affine::try_from_bytes(&g2.try_into_bytes()?)?;
        assert_eq!(g2, g2_2);
        Ok(())
    }

    #[test]
    fn gt_as_bytes() -> Result<(), FormatErr> {
        let grp = Bls12_381;
        let gt = grp.gen_random_msg_in_gt()?;
        let gt_2 = Gt::try_from_bytes(&gt.try_into_bytes()?)?;
        assert_eq!(gt, gt_2);
        Ok(())
    }
}
