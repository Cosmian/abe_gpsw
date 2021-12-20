use std::fmt::Display;

use super::{AbeScheme, AsBytes};
use crate::{bilinear_map::BilinearMap, error::FormatErr, msp::MonotoneSpanProgram};

// Master Private Key
#[derive(Debug, PartialEq)]
pub struct GpswMasterPrivateKey<G: BilinearMap> {
    t_i: Vec<G::Scalar>,
    y: G::Scalar,
}

// Master Public Key
#[derive(Debug, PartialEq, Clone)]
pub struct GpswMasterPublicKey<G: BilinearMap> {
    t_i: Vec<G::G2>,
    y: G::Gt,
}

// Master Public Delegation Key
#[derive(Debug, Clone, PartialEq)]
pub struct GpswMasterPublicDelegationKey<G: BilinearMap> {
    inv_t_i: Vec<G::G3>,
}

pub struct GpswMasterKey<G: BilinearMap> {
    pub priv_key: GpswMasterPrivateKey<G>,
    pub pub_key: GpswMasterPublicKey<G>,
    pub del_key: GpswMasterPublicDelegationKey<G>,
}

// Decryption Key
#[derive(Debug, Clone)]
pub struct GpswDecryptionKey<G: BilinearMap> {
    raw_d_i: Vec<G::G3>,
    // d_i prepared for miller loop
    d_i: Vec<G::G1>,
    msp: MonotoneSpanProgram<G::Scalar>,
}

impl<G: BilinearMap> Display for GpswDecryptionKey<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(bytes) = self.as_bytes() {
            write!(f, "{}", hex::encode(bytes))
        } else {
            write!(f, "Invalid input")
        }
    }
}

impl<G: BilinearMap> Display for GpswMasterPrivateKey<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(bytes) = self.as_bytes() {
            write!(f, "{}", hex::encode(bytes))
        } else {
            write!(f, "Invalid input")
        }
    }
}

impl<G: BilinearMap> Display for GpswMasterPublicKey<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(bytes) = self.as_bytes() {
            write!(f, "{}", hex::encode(bytes))
        } else {
            write!(f, "Invalid input")
        }
    }
}

impl<G: BilinearMap> Display for GpswMasterPublicDelegationKey<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(bytes) = self.as_bytes() {
            write!(f, "{}", hex::encode(bytes))
        } else {
            write!(f, "Invalid input")
        }
    }
}

// Ciphertext
pub struct GpswCiphertext<G: BilinearMap> {
    gamma: Vec<u32>,
    e_prime: G::Gt,
    e_i: Vec<G::G2>,
}

// No Eq for G1 but it is equivalent to G3
impl<G: BilinearMap> PartialEq for GpswDecryptionKey<G> {
    fn eq(&self, other: &Self) -> bool {
        (self.raw_d_i == other.raw_d_i) && (self.msp == other.msp)
    }
}

impl<G: BilinearMap> AsBytes for GpswMasterPrivateKey<G> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut t_i_bytes = self.t_i.as_bytes()?;
        let mut y_bytes = self.y.as_bytes()?;
        let mut res = Vec::with_capacity(t_i_bytes.len() + y_bytes.len());

        res.append(&mut t_i_bytes);
        res.append(&mut y_bytes);

        Ok(res)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let t_i = Vec::<G::Scalar>::from_bytes(bytes)?;
        let t_i_len = t_i.len_bytes();
        let y = G::Scalar::from_bytes(&bytes[t_i_len..])?;

        Ok(Self { t_i, y })
    }

    fn len_bytes(&self) -> usize {
        self.t_i.len_bytes() + self.y.len_bytes()
    }
}

impl<G: BilinearMap> AsBytes for GpswMasterPublicKey<G> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut t_i_bytes = self.t_i.as_bytes()?;
        let mut y_bytes = self.y.as_bytes()?;
        let mut res = Vec::with_capacity(t_i_bytes.len() + y_bytes.len());

        res.append(&mut t_i_bytes);
        res.append(&mut y_bytes);

        Ok(res)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let t_i = Vec::<G::G2>::from_bytes(bytes)?;
        let t_i_len = t_i.len_bytes();
        let y = G::Gt::from_bytes(&bytes[t_i_len..])?;

        Ok(Self { t_i, y })
    }

    fn len_bytes(&self) -> usize {
        self.t_i.len_bytes() + self.y.len_bytes()
    }
}

impl<G: BilinearMap> AsBytes for GpswMasterPublicDelegationKey<G> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut inv_t_i_bytes = self.inv_t_i.as_bytes()?;
        let mut res = Vec::with_capacity(inv_t_i_bytes.len());

        res.append(&mut inv_t_i_bytes);

        Ok(res)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let inv_t_i = Vec::<G::G3>::from_bytes(bytes)?;

        Ok(Self { inv_t_i })
    }

    fn len_bytes(&self) -> usize {
        self.inv_t_i.len_bytes()
    }
}

impl<G: BilinearMap> AsBytes for GpswDecryptionKey<G> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut raw_d_i_bytes = self.raw_d_i.as_bytes()?;
        let mut msp_bytes = self.msp.as_bytes()?;
        let mut res = Vec::with_capacity(raw_d_i_bytes.len() + msp_bytes.len());

        res.append(&mut raw_d_i_bytes);
        res.append(&mut msp_bytes);

        Ok(res)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let raw_d_i = Vec::<G::G3>::from_bytes(bytes)?;
        let raw_d_i_len = raw_d_i.len_bytes();
        let msp = MonotoneSpanProgram::<G::Scalar>::from_bytes(&bytes[raw_d_i_len..])?;
        let d_i = raw_d_i.iter().map(|g3| G::g3_to_g1(g3)).collect();

        Ok(Self { raw_d_i, d_i, msp })
    }

    fn len_bytes(&self) -> usize {
        self.raw_d_i.len_bytes() + self.msp.len_bytes()
    }
}

impl<G: BilinearMap> AsBytes for GpswCiphertext<G> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut gamma_bytes = self.gamma.as_bytes()?;
        let mut e_prime_bytes = self.e_prime.as_bytes()?;
        let mut e_i_bytes = self.e_i.as_bytes()?;
        let mut res = Vec::with_capacity(gamma_bytes.len() + e_prime_bytes.len() + e_i_bytes.len());

        res.append(&mut gamma_bytes);
        res.append(&mut e_i_bytes);
        res.append(&mut e_prime_bytes);

        Ok(res)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let gamma = Vec::<u32>::from_bytes(&bytes[0..])?;
        let gamma_len = gamma.len_bytes();
        let e_i = Vec::<G::G2>::from_bytes(&bytes[gamma_len..])?;
        let e_i_len = e_i.len_bytes();
        let e_prime = G::Gt::from_bytes(&bytes[gamma_len + e_i_len..])?;

        Ok(Self {
            gamma,
            e_prime,
            e_i,
        })
    }

    fn len_bytes(&self) -> usize {
        self.gamma.len_bytes() + self.e_i.len_bytes() + self.e_prime.len_bytes()
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Gpsw<G: BilinearMap> {
    group: G,
}

impl<G: BilinearMap + PartialEq> AbeScheme for Gpsw<G>
where
    GpswDecryptionKey<G>: Clone + std::fmt::Debug,
    GpswMasterPrivateKey<G>: std::fmt::Debug,
    GpswMasterPublicKey<G>: Clone + std::fmt::Debug,
    GpswMasterPublicDelegationKey<G>: Clone + std::fmt::Debug,
{
    type CipherText = GpswCiphertext<G>;
    // t_i, y
    type MasterPrivateKey = GpswMasterPrivateKey<G>;
    // g1^-t_i
    type MasterPublicDelegationKey = GpswMasterPublicDelegationKey<G>;
    // g2^t_i, g2^y
    type MasterPublicKey = GpswMasterPublicKey<G>;
    type PlainText = G::Gt;
    type UserDecryptionKey = GpswDecryptionKey<G>;

    fn description() -> String {
        format!("GPSW with {}", G::description())
    }

    fn generate_master_key(
        &self,
        size: usize,
    ) -> Result<
        (
            Self::MasterPrivateKey,
            Self::MasterPublicKey,
            Self::MasterPublicDelegationKey,
        ),
        FormatErr,
    > {
        let mk = self.generate_master_key(size)?;
        Ok((mk.priv_key, mk.pub_key, mk.del_key))
    }

    fn key_generation(
        &self,
        msp: &MonotoneSpanProgram<i32>,
        priv_key: &Self::MasterPrivateKey,
    ) -> Result<Self::UserDecryptionKey, FormatErr> {
        self.key_generation(msp, priv_key)
    }

    // if msp is None, just randomize the user-key
    fn key_delegation(
        &self,
        msp: &Option<MonotoneSpanProgram<i32>>,
        user_key: &GpswDecryptionKey<G>,
        del_key: &GpswMasterPublicDelegationKey<G>,
    ) -> Result<GpswDecryptionKey<G>, FormatErr> {
        msp.as_ref().map_or_else(
            || self.key_randomization(user_key, del_key),
            |m| self.key_delegation(m, user_key, del_key),
        )
    }

    fn generate_random_plaintext(&self) -> Result<Self::PlainText, FormatErr> {
        self.group.gen_random_msg_in_gt()
    }

    fn msg_encode(&self, msg: &[u8]) -> Result<Self::PlainText, FormatErr> {
        self.msg_encode(msg)
    }

    fn encrypt(
        &self,
        msg: &Self::PlainText,
        attr: &[u32],
        pub_key: &Self::MasterPublicKey,
    ) -> Result<Self::CipherText, FormatErr> {
        self.encrypt(msg, attr, pub_key)
    }

    fn decrypt(
        &self,
        enc: &Self::CipherText,
        key: &Self::UserDecryptionKey,
    ) -> Result<Option<Self::PlainText>, FormatErr> {
        self.decrypt(enc, key)
    }

    fn ciphertext_len(nb_attr: usize) -> usize {
        let gamma_len = 4 + (nb_attr * 4);
        // 48 is the size of a serialized element in Fp with |p|=381 bits.
        let ei_len = 4 + (nb_attr * 48);
        // 576 is the size of a serialized element in Fp^12 with |p|=381 bits.
        // and then 288 is the compressed size of a serialized element.
        let e_prime_len = 288;
        gamma_len + ei_len + e_prime_len
    }
}

impl<G: BilinearMap> Gpsw<G> {
    pub fn generate_master_key(&self, size: usize) -> Result<GpswMasterKey<G>, FormatErr> {
        let t_i = self.group.gen_random_scalar_vector(size)?;
        let y = self.group.gen_random_scalar()?;
        let big_y = self.group.gt_gen_exp(&y);
        let big_ti = self.group.g2_gen_exp_vector(&t_i);
        let inv_big_ti_g1 = self
            .group
            .g3_gen_exp_vector(&(t_i.iter().map(|ti| G::ONE / ti).collect::<Vec<_>>()));
        let priv_key = GpswMasterPrivateKey::<G> { t_i, y };
        let pub_key = GpswMasterPublicKey::<G> {
            t_i: big_ti,
            y: big_y,
        };
        let del_key = GpswMasterPublicDelegationKey::<G> {
            inv_t_i: inv_big_ti_g1,
        };
        Ok(GpswMasterKey {
            priv_key,
            pub_key,
            del_key,
        })
    }

    pub fn key_generation(
        &self,
        msp: &MonotoneSpanProgram<i32>,
        priv_key: &GpswMasterPrivateKey<G>,
    ) -> Result<GpswDecryptionKey<G>, FormatErr> {
        let u = match msp.cols() {
            0 => return Err(FormatErr::InternalOperation("empty MSP".to_string())),
            1 => vec![priv_key.y.clone()],
            x => {
                let mut u = self.group.gen_random_scalar_vector(x - 1)?;
                let u_l = u.iter().fold(G::ZERO, std::ops::Add::add);
                //u such that Σ u_i = y
                u.push(priv_key.y.clone() - &u_l);
                u
            }
        };
        // compute Di = g1^(<M_i, u>/-t_rho_i)
        let mut big_d_i = Vec::with_capacity(msp.rows());
        let mut big_raw_d_i = Vec::with_capacity(msp.rows());
        for (i, row) in msp.matrix().iter().enumerate() {
            let prod_scal = Self::prod_scal(&(*row), &u);
            let attribute = msp.get_attr_from_row(i) as usize;
            if attribute >= priv_key.t_i.len() {
                return Err(FormatErr::InternalOperation(
                    "Monotone Span Program is invalid: msp-row larger than private-key-t_i"
                        .to_string(),
                ))
            }
            let t_rho_i = &priv_key.t_i[attribute];
            let di = self.group.g1_gen_exp(&(prod_scal / t_rho_i));
            big_d_i.push(di.0);
            big_raw_d_i.push(di.1)
        }
        Ok(GpswDecryptionKey::<G> {
            raw_d_i: big_raw_d_i,
            d_i: big_d_i,
            msp: msp.into(),
        })
    }

    // assume the msp is more restrictive, otherwise the key will be useless
    pub fn key_delegation(
        &self,
        msp: &MonotoneSpanProgram<i32>,
        user_key: &GpswDecryptionKey<G>,
        del_key: &GpswMasterPublicDelegationKey<G>,
    ) -> Result<GpswDecryptionKey<G>, FormatErr> {
        let u = match msp.cols() {
            0 => return Err(FormatErr::InternalOperation("empty MSP".to_string())),
            1 => vec![G::ZERO],
            x => {
                let mut u = self.group.gen_random_scalar_vector(x - 1)?;
                let u_l = u.iter().fold(G::ZERO, std::ops::Add::add);
                //u such that Σ u_i = 0
                u.push(-u_l);
                u
            }
        };
        // compute Di = g1^(<M_i, u>/-t_rho_i) = (g1^(t_rho_i)^-1)^(<M_i, u>)
        let mut big_d_i = Vec::with_capacity(msp.rows());
        let mut raw_big_d_i = Vec::with_capacity(msp.rows());
        for (i, row) in msp.matrix().iter().enumerate() {
            let prod_scal = Self::prod_scal(&(*row), &u);
            let gt_rho_i = &del_key.inv_t_i[msp.get_attr_from_row(i) as usize];
            let di = self.group.g3_exp(gt_rho_i, &prod_scal);
            //randomize key
            if let Some(index) = user_key.msp.get_row_from_attr(msp.get_attr_from_row(i)) {
                let r_di = self.group.g3_mul(&user_key.raw_d_i[index], &di);
                big_d_i.push(r_di.0);
                raw_big_d_i.push(r_di.1);
            } else {
                return Err(FormatErr::InternalOperation(
                    "new attribute is not allowed".to_string(),
                ))
            }
        }
        Ok(GpswDecryptionKey::<G> {
            raw_d_i: raw_big_d_i,
            d_i: big_d_i,
            msp: msp.into(),
        })
    }

    // assume the msp is more restrictive, otherwise the key will be useless
    pub fn key_randomization(
        &self,
        user_key: &GpswDecryptionKey<G>,
        del_key: &GpswMasterPublicDelegationKey<G>,
    ) -> Result<GpswDecryptionKey<G>, FormatErr> {
        let msp = &user_key.msp;
        let u = match msp.cols() {
            0 => return Err(FormatErr::InternalOperation("empty MSP".to_string())),
            1 => vec![G::ZERO],
            x => {
                let mut u = self.group.gen_random_scalar_vector(x - 1)?;
                let u_l = u.iter().fold(G::ZERO, std::ops::Add::add);
                //u such that Σ u_i = 0
                u.push(-u_l);
                u
            }
        };
        // compute Di = g1^(<M_i, u>/-t_rho_i) = (g1^(t_rho_i)^-1)^(<M_i, u>)
        let mut big_d_i = Vec::with_capacity(msp.rows());
        let mut raw_big_d_i = Vec::with_capacity(msp.rows());
        for (i, row) in msp.matrix().iter().enumerate() {
            let prod_scal = Self::prod_scal(&(*row), &u);
            let gt_rho_i = &del_key.inv_t_i[msp.get_attr_from_row(i) as usize];
            let di = self.group.g3_exp(gt_rho_i, &prod_scal);
            //randomize key
            if let Some(index) = user_key.msp.get_row_from_attr(msp.get_attr_from_row(i)) {
                let r_di = self.group.g3_mul(&user_key.raw_d_i[index], &di);
                big_d_i.push(r_di.0);
                raw_big_d_i.push(r_di.1);
            } else {
                return Err(FormatErr::InternalOperation(
                    "new attribute is not allowed".to_string(),
                ))
            }
        }
        Ok(GpswDecryptionKey::<G> {
            raw_d_i: raw_big_d_i,
            d_i: big_d_i,
            msp: (*msp).clone(),
        })
    }

    pub fn msg_encode(&self, msg: &[u8]) -> Result<G::Gt, FormatErr> {
        self.group.msg_to_gt(msg)
    }

    pub fn encrypt(
        &self,
        msg: &G::Gt,
        gamma: &[u32],
        pub_key: &GpswMasterPublicKey<G>,
    ) -> Result<GpswCiphertext<G>, FormatErr> {
        if pub_key.t_i.len() <= gamma.len() {
            return Err(FormatErr::InternalOperation(format!(
                "invalid attributes: gamma value incorrect (value: {}, max expected size: {})",
                gamma.len(),
                pub_key.t_i.len() - 1
            )))
        }
        let s = self.group.gen_random_scalar()?;
        let e_prime = self.group.gt_mul(msg, &self.group.gt_exp(&pub_key.y, &s));
        let e_i = gamma
            .iter()
            .map(|i| self.group.g2_exp(&pub_key.t_i[*i as usize], &s))
            .collect();
        let enc_msg = GpswCiphertext::<G> {
            gamma: gamma.to_vec(),
            e_prime,
            e_i,
        };
        Ok(enc_msg)
    }

    pub fn decrypt(
        &self,
        enc: &GpswCiphertext<G>,
        key: &GpswDecryptionKey<G>,
    ) -> Result<Option<G::Gt>, FormatErr> {
        // extract the submatrix corresponding to gamma
        // and the corresponding d_i and e_i
        let mut matrix = Vec::new();
        let mut d_i = Vec::new();
        let mut e_i = Vec::new();
        for (i, attr) in enc.gamma.iter().enumerate() {
            if let Some(row) = key.msp.get_row_from_attr(*attr) {
                matrix.push(key.msp.get_row(row).clone());
                d_i.push(&key.d_i[row]);
                e_i.push(&enc.e_i[i]);
            }
        }
        // find the α_i coefficients if any
        let a_i = Self::span_coefs(&mut matrix)?;
        // keep the α_i != 0 and the corresponding (e_i, d_i)
        a_i.map_or(Ok(None), |a_i| {
            let d_i = d_i
                .iter()
                .enumerate()
                .filter_map(|(i, di)| if a_i[i] == G::ZERO { None } else { Some(*di) })
                .collect::<Vec<_>>();
            let e_i = e_i
                .iter()
                .enumerate()
                .filter_map(|(i, ei)| if a_i[i] == G::ZERO { None } else { Some(*ei) })
                .collect::<Vec<_>>();
            let a_i = a_i.iter().filter(|ai| **ai != G::ZERO).collect::<Vec<_>>();
            // compute Π e(d_i,e_i)^α_i
            let prod = self
                .group
                .prod_gt_exp(d_i.as_slice(), e_i.as_slice(), a_i.as_slice());
            // Recover the msg
            Ok(Some(self.group.gt_div(&enc.e_prime, &prod)))
        })
    }

    // assume v1.len() = v2.len()
    fn prod_scal<T: Clone + Into<G::Scalar>>(v1: &[T], v2: &[G::Scalar]) -> G::Scalar {
        v1.iter()
            .zip(v2.iter())
            .map(|(u1, u2)| (*u1).clone().into() * u2)
            .reduce(|a, b| a + &b)
            .unwrap_or(G::ZERO)
    }

    // Compute a linear combination of row which span to 1,⋯,1 vector
    // It is equivalent to solve the linear system: matrix⋅x = 1,⋯,1
    // We use a Gauss-Jordan Elimination
    // note that we do the elimination on the transpose
    pub fn span_coefs(
        matrix: &mut Vec<Vec<G::Scalar>>,
    ) -> Result<Option<Vec<G::Scalar>>, FormatErr> {
        // Add the result vector 1,⋯,1 to the matrix
        if matrix.is_empty() || matrix[0].is_empty() {
            return Err(FormatErr::InternalOperation(
                "empty input matrix".to_string(),
            ))
        }
        let mut vec_res = Vec::with_capacity(matrix[0].len());
        vec_res.resize(matrix[0].len(), G::ONE);
        matrix.push(vec_res);
        // current row for elimination
        let mut curr_row = 0;
        // current_col for pivot
        let mut curr_col = 0;
        let nb_col = matrix.len();
        let nb_row = matrix[0].len();
        let mut last_pivot_col = 0;
        loop {
            if curr_col == nb_col || curr_row == nb_row {
                break
            }
            // search for the first non-zero in the current columns
            let mut row = None;
            // transpose
            for r in curr_row..nb_row {
                let tmp = &matrix[curr_col][r];
                if *tmp != G::ZERO {
                    row = Some(r);
                    break
                }
            }

            if let Some(row) = row {
                // swap
                for col in matrix.iter_mut() {
                    col.swap(curr_row, row);
                }

                // divide (on the Scalar field)
                if matrix[curr_col][curr_row] != G::ONE {
                    let index_val = std::mem::replace(&mut matrix[curr_col][curr_row], G::ONE);
                    for col in matrix.iter_mut().skip(curr_col + 1) {
                        // TODO: Is it possible to avoir this clone ?
                        // At the moment, No (we can use std::mem::replace)
                        col[curr_row] = col[curr_row].clone() / &index_val;
                    }
                }
                // eliminate
                for r in curr_row + 1..nb_row {
                    let index = (matrix[curr_col][r]).clone();
                    if index != G::ZERO {
                        for col in matrix.iter_mut().skip(curr_col) {
                            // TODO: avoid index.clone if possible
                            col[r] = col[r].clone() - &(index.clone() * &(col[curr_row]))
                        }
                    }
                }
                // reverse side
                for r in 0..curr_row {
                    let index = (matrix[curr_col][r]).clone();
                    if index != G::ZERO {
                        for col in matrix.iter_mut().skip(curr_col) {
                            // TODO: avoid index.clone if possible
                            col[r] = col[r].clone() - &(index.clone() * &(col[curr_row]))
                        }
                    }
                }
                // next
                last_pivot_col = curr_col;
                curr_row += 1;
            }
            curr_col += 1
            // is it the end ?
        }

        // the last pivot is in the last column so no solution
        if last_pivot_col == nb_col - 1 {
            return Ok(None)
        }
        let mut sol = Vec::with_capacity(nb_col);
        let mut current_col = 0;
        'outer: for i in 0..nb_row {
            while matrix[current_col][i] == G::ZERO {
                current_col += 1;
                sol.push(G::ZERO);
                if current_col == nb_col {
                    break 'outer
                }
            }
            if matrix[current_col][i] == G::ONE {
                current_col += 1;
                sol.push(matrix.last().unwrap()[i].clone());
            } else {
                panic!("error");
            }
            if current_col == nb_col {
                break 'outer
            }
        }
        sol.resize(nb_col - 1, G::ZERO);
        Ok(Some(sol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bilinear_map::bls12_381::Bls12_381,
        msp::{
            Node,
            Node::{And, Leaf, Or},
        },
    };

    #[test]
    fn encrypt_decrypt() -> Result<(), FormatErr> {
        let a = Box::new(Leaf(1));
        let b = Box::new(Leaf(2));
        let c = Box::new(Leaf(3));
        let d = Box::new(Leaf(4));
        let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
        println!("formula: {}", formula);
        let msp = formula.to_msp()?;
        println!("msp: {}", msp);

        let abe = Gpsw {
            group: Bls12_381::default(),
        };

        let mk = abe.generate_master_key(10)?;
        let uk = abe.key_generation(&msp, &mk.priv_key)?;
        let message = abe.msg_encode("test".as_bytes())?;
        let gamma = [1, 4];
        let enc = abe.encrypt(&message, &gamma, &mk.pub_key)?;

        println!("decrypt");
        let dec = abe.decrypt(&enc, &uk)?.expect("decrypt failed");
        println!("\nDecryption Ok: {}", message == dec);
        Ok(())
    }

    #[test]
    fn user_key_as_bytes() -> Result<(), FormatErr> {
        let a = Box::new(Leaf(1));
        let b = Box::new(Leaf(2));
        let c = Box::new(Leaf(3));
        let d = Box::new(Leaf(4));
        let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
        println!("formula: {}", formula);
        let msp = formula.to_msp()?;
        println!("msp: {}", msp);

        let abe = Gpsw {
            group: Bls12_381::default(),
        };

        let mk = abe.generate_master_key(10)?;
        let uk = abe.key_generation(&msp, &mk.priv_key)?;
        let uk_2 = GpswDecryptionKey::<Bls12_381>::from_bytes(&uk.as_bytes()?)?;

        assert_eq!(uk.msp, uk_2.msp);
        assert_eq!(uk.raw_d_i, uk_2.raw_d_i);
        Ok(())
    }

    #[test]
    fn ciphertext_as_bytes() -> Result<(), FormatErr> {
        let a = Box::new(Leaf(1));
        let b = Box::new(Leaf(2));
        let c = Box::new(Leaf(3));
        let d = Box::new(Leaf(4));
        let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
        println!("formula: {}", formula);
        let msp = formula.to_msp()?;
        println!("msp: {}", msp);

        let abe = Gpsw {
            group: Bls12_381::default(),
        };

        let mk = abe.generate_master_key(10)?;
        let message = abe.msg_encode("test".as_bytes())?;
        let gamma = [1, 4];
        let enc = abe.encrypt(&message, &gamma, &mk.pub_key)?;
        let enc_2 = GpswCiphertext::<Bls12_381>::from_bytes(&enc.as_bytes()?)?;

        assert_eq!(enc.gamma, enc_2.gamma);
        assert_eq!(enc.e_prime, enc_2.e_prime);
        assert_eq!(enc.e_i, enc_2.e_i);
        Ok(())
    }

    #[test]
    fn master_public_key_as_bytes() -> Result<(), FormatErr> {
        let a = Box::new(Leaf(1));
        let b = Box::new(Leaf(2));
        let c = Box::new(Leaf(3));
        let d = Box::new(Leaf(4));
        let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
        println!("formula: {}", formula);
        let msp = formula.to_msp()?;
        println!("msp: {}", msp);

        let abe = Gpsw {
            group: Bls12_381::default(),
        };

        let mk = abe.generate_master_key(10)?;
        let mpk = mk.pub_key;
        let mpk_2 = GpswMasterPublicKey::<Bls12_381>::from_bytes(&mpk.as_bytes()?)?;

        assert_eq!(mpk.t_i, mpk_2.t_i);
        assert_eq!(mpk.y, mpk_2.y);
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_with_multiple_key_pair() -> Result<(), FormatErr> {
        let policy_1 = Node::parse("1 | 2")?.to_msp()?;
        let policy_2 = Node::parse("1 & 2")?.to_msp()?;
        let policy_3 = Node::parse("1")?.to_msp()?;
        let policy_4 = Node::parse("1 & 3")?.to_msp()?;
        let policy_5 = Node::parse("1 | 3")?.to_msp()?;

        let abe = Gpsw {
            group: Bls12_381::default(),
        };

        let mk = abe.generate_master_key(10)?;
        let uk = abe.key_generation(&policy_1, &mk.priv_key)?;
        let uk2 = abe.key_generation(&policy_2, &mk.priv_key)?;
        let uk3 = abe.key_generation(&policy_3, &mk.priv_key)?;
        let uk4 = abe.key_generation(&policy_4, &mk.priv_key)?;
        let uk5 = abe.key_generation(&policy_5, &mk.priv_key)?;

        println!("msp 1: {}", uk.msp);
        println!("msp 2: {}", uk2.msp);
        println!("msp 2: {}", uk3.msp);
        println!("msp 2: {}", uk4.msp);

        let msg = abe.msg_encode("test".as_bytes())?;

        let gamma = [1, 2];
        let enc = abe.encrypt(&msg, &gamma, &mk.pub_key)?;

        let dec = abe.decrypt(&enc, &uk)?.expect("decrypt failed");
        assert_eq!(msg, dec);
        println!("\nDecryption Ok: {}", msg == dec);

        let dec2 = abe.decrypt(&enc, &uk2)?.expect("decrypt failed");
        assert_eq!(msg, dec2);
        println!("\nDecryption Ok: {}", msg == dec2);

        let dec3 = abe.decrypt(&enc, &uk3)?.expect("decrypt failed");
        assert_eq!(msg, dec3);
        println!("\nDecryption Ok: {}", msg == dec3);

        let dec4 = abe.decrypt(&enc, &uk4)?;
        assert_eq!(dec4, None);

        let dec5 = abe.decrypt(&enc, &uk5)?.expect("decrypt failed");
        assert_eq!(msg, dec5);
        println!("\nDecryption Ok: {}", msg == dec5);

        Ok(())
    }

    #[test]
    fn master_private_key_as_bytes() -> Result<(), FormatErr> {
        let abe = Gpsw {
            group: Bls12_381::default(),
        };
        let mk = abe.generate_master_key(10)?;
        let mpk = mk.priv_key;
        let mpk_2 = GpswMasterPrivateKey::<Bls12_381>::from_bytes(&mpk.as_bytes()?)?;

        assert_eq!(mpk.t_i, mpk_2.t_i);
        assert_eq!(mpk.y, mpk_2.y);
        Ok(())
    }

    #[test]
    fn master_public_delegation_key_as_bytes() -> Result<(), FormatErr> {
        let abe = Gpsw {
            group: Bls12_381::default(),
        };
        let mk = abe.generate_master_key(10)?;
        let mpk = mk.del_key;
        let mpk_2 = GpswMasterPublicDelegationKey::<Bls12_381>::from_bytes(&mpk.as_bytes()?)?;

        assert_eq!(mpk.inv_t_i, mpk_2.inv_t_i);
        Ok(())
    }
}
