use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Display,
    ops::{BitAnd, BitOr},
};

use regex::Regex;

use crate::gpsw::AsBytes;

#[derive(Clone, PartialEq, Debug)]
pub struct MonotoneSpanProgram<I> {
    pub(crate) nb_row: usize,
    pub(crate) nb_col: usize,
    pub(crate) matrix: Vec<Vec<I>>,
    pub(crate) attr_to_row: HashMap<u32, usize>,
    pub(crate) row_to_attr: Vec<u32>,
}

// Convert an string-array with only integer values to a real array
pub fn attributes_parse(range: &str) -> eyre::Result<Vec<u32>> {
    // remove all whitespaces
    let mut clean_str: String = range.split_whitespace().collect();
    // check for outers bracket
    if let Some(c) = clean_str.pop() {
        eyre::ensure!(
            c == ']',
            "attribute range parsing error: Last character must be `]`"
        );
    } else {
        eyre::bail!("attribute range parsing error: empty string")
    }
    eyre::ensure!(
        clean_str.remove(0) == '[',
        "attribute range parsing error: First character must be `[`"
    );
    let vec = clean_str
        .split(',')
        .map(|item| {
            let mut interval = item.split('-');
            let start = if let Some(b) = interval.next() {
                b.parse::<u32>()?
            } else {
                eyre::bail!("wrong range")
            };
            let end = if let Some(b) = interval.next() {
                b.parse::<u32>()?
            } else {
                start
            };
            Ok((start..=end).collect::<Vec<u32>>())
        })
        .collect::<eyre::Result<Vec<Vec<u32>>, _>>()?;
    // `flat_map` does not works with `Result` thus we must `flatten` after
    // `collect` above
    let vec = vec.into_iter().flatten().collect();

    Ok(vec)
}

impl<I: AsBytes> AsBytes for MonotoneSpanProgram<I> {
    fn as_bytes(&self) -> eyre::Result<Vec<u8>> {
        let mut res = Vec::with_capacity(
            8 + (self.nb_row * self.nb_col * self.matrix[0][0].len_bytes()) + (self.nb_row * 4),
        );
        res.append(&mut u32::try_from(self.nb_row)?.to_be_bytes().to_vec());
        res.append(&mut u32::try_from(self.nb_col)?.to_be_bytes().to_vec());
        for u in &self.row_to_attr {
            res.append(&mut (*u).to_be_bytes().to_vec())
        }
        for r in &self.matrix {
            for c in r {
                res.append(&mut c.as_bytes()?);
            }
        }

        Ok(res)
    }

    fn from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        if bytes.len() < 8 {
            eyre::bail!("wrong size");
        }
        let mut nb_row = [0_u8; 4];
        nb_row.copy_from_slice(&bytes[0..4]);
        let nb_row = u32::from_be_bytes(nb_row) as usize;
        let mut nb_col = [0_u8; 4];
        nb_col.copy_from_slice(&bytes[4..8]);
        let nb_col = u32::from_be_bytes(nb_col) as usize;

        if bytes.len() < 8 + 4 * nb_row {
            eyre::bail!("wrong size");
        }
        let mut row_to_attr = Vec::with_capacity(nb_row);
        let mut attr_to_row = HashMap::with_capacity(nb_row);
        for i in 0..nb_row {
            let mut u = [0_u8; 4];
            u.copy_from_slice(&bytes[8 + i * 4..12 + i * 4]);
            let u = u32::from_be_bytes(u);
            row_to_attr.push(u);
            if attr_to_row.insert(u, i).is_some() {
                eyre::bail!("Error deserialize MSP: leaf already inserted")
            }
        }

        let mut matrix = Vec::with_capacity(nb_row);
        let mut row = Vec::with_capacity(nb_col);
        row.push(I::from_bytes(&bytes[8 + (4 * nb_row)..])?);
        if bytes.len() < 8 + (4 * nb_row) + (nb_row * nb_col * row[0].len_bytes()) {
            eyre::bail!("wrong size");
        }
        for c in 1..nb_col {
            let index = 8 + (4 * nb_row) + (c * row[0].len_bytes());
            row.push(I::from_bytes(&bytes[index..])?);
        }
        matrix.push(row);
        for r in 1..nb_row {
            let mut row = Vec::with_capacity(nb_col);
            for c in 0..nb_col {
                let index = 8 + (4 * nb_row) + (((r * nb_col) + c) * matrix[0][0].len_bytes());
                row.push(I::from_bytes(&bytes[index..])?);
            }
            matrix.push(row);
        }
        Ok(Self {
            nb_row,
            nb_col,
            matrix,
            attr_to_row,
            row_to_attr,
        })
    }

    fn len_bytes(&self) -> usize {
        8 + (self.nb_row * self.nb_col * self.matrix[0][0].len_bytes()) + (self.nb_row * 4)
    }
}

impl<I: std::fmt::Debug> Display for MonotoneSpanProgram<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        for (attr, row) in self.row_to_attr.iter().zip(self.matrix.iter()) {
            writeln!(f, "attr {:>4}: {:?}", attr, *row)?;
        }
        Ok(())
    }
}

impl<I> MonotoneSpanProgram<I> {
    #[must_use]
    pub fn cols(&self) -> usize {
        self.nb_col
    }

    #[must_use]
    pub fn rows(&self) -> usize {
        self.nb_row
    }

    #[must_use]
    pub fn matrix(&self) -> &Vec<Vec<I>> {
        &self.matrix
    }

    #[must_use]
    pub fn get_row(&self, row: usize) -> &Vec<I> {
        &self.matrix[row]
    }

    #[must_use]
    pub fn get_attr_from_row(&self, i: usize) -> u32 {
        self.row_to_attr[i]
    }

    #[must_use]
    pub fn get_row_from_attr(&self, attr: u32) -> Option<usize> {
        self.attr_to_row.get(&attr).copied()
    }
}

impl<I: From<i32>> MonotoneSpanProgram<I>
where
    MonotoneSpanProgram<I>: From<MonotoneSpanProgram<i32>>,
{
    pub fn parse(s: &str) -> eyre::Result<Self> {
        let msp = Node::parse(s)?.to_msp()?;
        Ok(Self::from(msp))
    }
}

impl<I1: From<i32>> From<&MonotoneSpanProgram<i32>> for MonotoneSpanProgram<I1> {
    fn from(msp: &MonotoneSpanProgram<i32>) -> Self {
        Self {
            nb_row: msp.nb_row,
            nb_col: msp.nb_col,
            attr_to_row: msp.attr_to_row.clone(),
            row_to_attr: msp.row_to_attr.clone(),
            matrix: msp
                .matrix()
                .iter()
                .map(|v| v.iter().map(|i| (*i).into()).collect())
                .collect(),
        }
    }
}

#[derive(Clone)]
pub enum Node {
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Leaf(u32),
}

// use A & B to construct And(A, B)
impl BitAnd for Node {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::And(Box::new(self), Box::new(rhs))
    }
}

// use A | B to construct Or(A, B)
impl BitOr for Node {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::Or(Box::new(self), Box::new(rhs))
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Node::And(n1, n2) => format!("AND( {}, {} )", n1, n2),
            Node::Or(n1, n2) => format!("OR( {}, {} )", n1, n2),
            Node::Leaf(v) => format!("LEAF({})", v),
        };
        write!(f, "{}", str)
    }
}

impl Node {
    // from https://eprint.iacr.org/2010/351.pdf annex G
    // TODO: Ensure each Attribute appears only once in the Formula
    // TODO: Should we use Disjonctive Normal Form?
    pub fn to_msp(&self) -> eyre::Result<MonotoneSpanProgram<i32>> {
        let mut counter = 1;
        let mut queue = std::collections::VecDeque::new();
        let mut matrix = Vec::new();
        // compute the msp matrix
        queue.push_back((self, vec![1]));
        while let Some((node, vector)) = queue.pop_front() {
            match node {
                Node::And(n1, n2) => {
                    let mut vec_1 = vector.clone();
                    vec_1.resize(counter, 0_i32);
                    vec_1.push(1);
                    queue.push_back((n1, vec_1));
                    let mut vec_2 = vec![0_i32; counter];
                    vec_2.push(-1_i32);
                    queue.push_back((n2, vec_2));
                    counter += 1;
                }
                Node::Or(n1, n2) => {
                    queue.push_back((n1, vector.clone()));
                    queue.push_back((n2, vector.clone()));
                }
                leaf @ Node::Leaf(_) => {
                    matrix.push((leaf, vector.clone()));
                }
            };
        }
        // The resulting matrix span to the vector 1,0,⋯,0
        // For our scheme we need the msp to span the vector 1,⋯,1
        // Thus we have to change the basis such that 1,0,⋯,0 becomes 1,1,⋯1. That is
        // multiply the change-of-basis matrix 1 0 0 0 ⋯ 0
        // 1 1 0 0 ⋯ 0
        // 1 0 1 0 ⋯ 0
        // ⋯ ⋯ ⋯ ⋯ ⋯
        // 1 0 0 ⋯ ⋯ 1
        // by the transpose of msp_matrix
        // Finally it is equivalent to add the first column to the others
        let mut msp_matrix = Vec::with_capacity(matrix.len());
        let mut msp_map = HashMap::with_capacity(matrix.len());
        let mut msp_vec = Vec::with_capacity(matrix.len());
        for (i, row) in matrix.iter().enumerate() {
            if let Node::Leaf(attr) = row.0 {
                let mut vec = row.1.clone();
                vec.resize(counter, 0);
                for i in 1..vec.len() {
                    vec[i] += vec[0];
                }
                msp_matrix.push(vec);
                msp_vec.push(*attr);
                if msp_map.insert(*attr, i).is_some() {
                    eyre::bail!("Error constructing MSP: leaf already inserted")
                }
            } else {
                eyre::bail!("Error constructing MSP: only leaf allowed")
            }
        }
        Ok(MonotoneSpanProgram {
            nb_row: msp_matrix.len(),
            nb_col: counter,
            matrix: msp_matrix,
            attr_to_row: msp_map,
            row_to_attr: msp_vec,
        })
    }

    // Very basic parser, the expression must be well formed
    // Example: convert the string "1 & (4 | (2 & 3))" to And(a, Box::new(Or(d,
    // Box::new(And(b, c))))) In this implementation, only digits are allowed
    // and parenthesis is expected to respect the operators priorities
    pub fn parse(s: &str) -> eyre::Result<Self> {
        // Authorize only digits and operators & and |
        let authorized = [
            ' ', '(', ')', '&', '|', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        ];
        if s.is_empty() || s.chars().any(|c| !authorized.contains(&c)) {
            eyre::bail!(
                "Formula must contain only digits, parenthesis and operators & and |. Given \
                 formula: {}",
                s
            )
        }
        // Remove all spaces
        let new_s = str::replace(s, " ", "");

        // Try getting first integer and then following operation
        let int_reg = Regex::new(r"^\d+")?;
        if int_reg.is_match(&new_s) {
            if int_reg.captures_len() != 1 {
                eyre::bail!("Invalid formula")
            }
            let integer_str = int_reg
                .find_at(&new_s, 0)
                .ok_or_else(|| {
                    eyre::eyre!("Integer detected by regex but not found in: {}", &new_s)
                })?
                .as_str();
            let integer = integer_str.parse::<u32>()?;

            // Remove integer from current formula
            let new_s = &new_s[integer_str.len()..];
            if new_s.is_empty() {
                return Ok(Node::Leaf(integer))
            }
            let a = Box::new(Node::Leaf(integer));
            let operator = new_s.chars().next().ok_or_else(|| {
                eyre::eyre!(
                    "No further character while detecting operator in: {}",
                    &new_s
                )
            })?;

            // Remove operator from input string
            let new_s = &new_s[1..];
            match operator {
                '&' => Ok(Node::And(a, Box::new(Node::parse(new_s)?))),
                '|' => Ok(Node::Or(a, Box::new(Node::parse(new_s)?))),
                _ => eyre::bail!("Invalid formula: operator expected"),
            }
        } else {
            // Remove parenthesis on current part of formula and continue
            let first_char = new_s.chars().next().ok_or_else(|| {
                eyre::eyre!(
                    "No further character while getting first char in: {}",
                    &new_s
                )
            })?;
            let new_s = &new_s[1..];
            if first_char != '(' {
                eyre::bail!("Invalid formula: opening parenthesis expected")
            }

            // Check if formula contains a closing parenthesis
            let c = new_s.matches(')').count();
            if c == 0 {
                eyre::bail!("Invalid formula: closing parenthesis expected")
            }

            // Search right closing parenthesis, avoiding false positive
            let mut count = 0;
            let mut right_closing_parenthesis = 0;
            for (index, c) in new_s.chars().enumerate() {
                match c {
                    '(' => count += 1,
                    ')' => count -= 1,
                    _ => {}
                };
                if count < 0 {
                    right_closing_parenthesis = index;
                    break
                }
            }

            let between_parenthesis = &new_s[..right_closing_parenthesis];
            let new_s = &new_s[between_parenthesis.len()..];

            // Skip closing parenthesis
            let new_s = &new_s[1..];
            if new_s.is_empty() {
                return Node::parse(between_parenthesis)
            }
            let operator = new_s.chars().next().ok_or_else(|| {
                eyre::eyre!(
                    "No further character while detecting operator in: {}",
                    &new_s
                )
            })?;
            let new_s = &new_s[1..];

            match operator {
                '&' => Ok(Node::And(
                    Box::new(Node::parse(between_parenthesis)?),
                    Box::new(Node::parse(new_s)?),
                )),
                '|' => Ok(Node::Or(
                    Box::new(Node::parse(between_parenthesis)?),
                    Box::new(Node::parse(new_s)?),
                )),
                _ => eyre::bail!("Invalid formula: operator expected"),
            }
        }
    }
} // impl Node
