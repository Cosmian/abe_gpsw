use core::ops::{Add, Div, Mul, Neg, Sub};

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::{core::gpsw::AsBytes, error::FormatErr};

pub mod bls12_381;

// bilinear map: G1 x G2 -> Gt
// G1, G2 and Gt are used with as multiplicative notation
// G1 is involved in the key generation
// G2 is involved in the encryption process
// Gt is involved in decryption
// G3 is involved in the key delegation, usually equivalent to G1
//    (G1 is usually proprocessed to ease pairing)
pub trait BilinearMap: Default {
    // underlying prime field element
    type Scalar: From<i32>
        + for<'a> Add<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Sub<&'a Self::Scalar, Output = Self::Scalar>
        + Neg<Output = Self::Scalar>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Div<&'a Self::Scalar, Output = Self::Scalar>
        + Clone
        + PartialEq
        + std::fmt::Debug
        + AsBytes;

    // element of the group G1
    type G1;

    // element of the group G2
    type G2: AsBytes + PartialEq;

    // element of group G3
    type G3: AsBytes + PartialEq;

    // element of the group Gt
    type Gt: AsBytes + PartialEq;

    const ZERO: Self::Scalar;
    const ONE: Self::Scalar;

    fn description() -> String;

    //
    // Functions that must be implemented
    //
    // Scalar
    // generate a random scalar on the primary field
    fn gen_rand_scalar_inner<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<Self::Scalar, FormatErr>;

    fn gen_rand_gt_inner<R: CryptoRng + RngCore>(&self, rng: &mut R)
    -> Result<Self::Gt, FormatErr>;

    fn msg_to_scalar(&self, msg: &[u8]) -> Result<Self::Scalar, FormatErr>;

    // Group
    // compute g1^x
    fn g1_gen_exp(&self, x: &Self::Scalar) -> (Self::G1, Self::G3);
    fn g3_gen_exp(&self, x: &Self::Scalar) -> Self::G3;
    // compute a x b where a and b \in G3
    fn g3_mul(&self, a: &Self::G3, b: &Self::G3) -> (Self::G1, Self::G3);
    // compute a^x where a \in G3
    fn g3_exp(&self, a: &Self::G3, x: &Self::Scalar) -> Self::G3;

    // compute g2^x
    fn g2_gen_exp(&self, x: &Self::Scalar) -> Self::G2;

    // compute a^x where a \in G2
    fn g2_exp(&self, a: &Self::G2, x: &Self::Scalar) -> Self::G2;

    // compute e(g1,g2)^x
    fn gt_gen_exp(&self, x: &Self::Scalar) -> Self::Gt;

    // compute a^x where a \in Gt
    fn gt_exp(&self, a: &Self::Gt, x: &Self::Scalar) -> Self::Gt;

    // compute a x b where a and b \in Gt
    fn gt_mul(&self, a: &Self::Gt, b: &Self::Gt) -> Self::Gt;

    // compute a / b where a and b \in Gt
    fn gt_div(&self, a: &Self::Gt, b: &Self::Gt) -> Self::Gt;

    // compute Π e(d_i,e_i)^α_i where e is the pairing G1 x G2 -> Gt
    fn prod_gt_exp(&self, d_i: &[&Self::G1], e_i: &[&Self::G2], a_i: &[&Self::Scalar]) -> Self::Gt;

    fn g3_to_g1(v: &Self::G3) -> Self::G1;
    //
    // Derived functions
    //
    fn gen_random_scalar(&self) -> Result<Self::Scalar, FormatErr> {
        let mut rng = rand_hc::Hc128Rng::from_entropy();
        self.gen_rand_scalar_inner(&mut rng)
    }

    fn gen_random_scalar_vector(&self, size: usize) -> Result<Vec<Self::Scalar>, FormatErr> {
        let mut rng = rand_hc::Hc128Rng::from_entropy();
        std::iter::repeat_with(|| self.gen_rand_scalar_inner(&mut rng))
            .take(size)
            .collect()
    }

    fn g3_gen_exp_vector(&self, vec_x: &[Self::Scalar]) -> Vec<Self::G3> {
        vec_x.iter().map(|x| self.g3_gen_exp(x)).collect()
    }

    fn g2_gen_exp_vector(&self, vec_x: &[Self::Scalar]) -> Vec<Self::G2> {
        vec_x.iter().map(|x| self.g2_gen_exp(x)).collect()
    }

    fn msg_to_gt(&self, msg: &[u8]) -> Result<Self::Gt, FormatErr> {
        let scl = self.msg_to_scalar(msg)?;
        Ok(self.gt_gen_exp(&scl))
    }

    fn gen_random_msg_in_gt(&self) -> Result<Self::Gt, FormatErr> {
        let mut rng = rand_hc::Hc128Rng::from_entropy();
        self.gen_rand_gt_inner(&mut rng)
    }
}
