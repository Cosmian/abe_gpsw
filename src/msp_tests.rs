use crate::{
    error::FormatErr,
    gpsw::AsBytes,
    msp::{
        MonotoneSpanProgram, Node,
        Node::{And, Leaf, Or},
    },
};

fn to_msp(val: &str) -> Result<MonotoneSpanProgram<i32>, FormatErr> {
    Node::parse(val)?.to_msp()
}

#[test]
fn parsing() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));

    let a_msp = Box::new(Leaf(1)).to_msp()?;
    let a_and_b_msp = Box::new(And(Box::new(Leaf(1)), Box::new(Leaf(2)))).to_msp()?;
    let a_or_b_msp = Box::new(Or(Box::new(Leaf(1)), Box::new(Leaf(2)))).to_msp()?;

    assert_eq!(to_msp("1")?, a_msp);
    assert_eq!(to_msp("1&2")?, a_and_b_msp);
    assert_eq!(to_msp(" 1 | 2 ")?, a_or_b_msp);
    assert_eq!(to_msp("(1&2)")?, a_and_b_msp);
    assert_eq!(to_msp("((1&2))")?, a_and_b_msp);
    assert_eq!(to_msp("((1)&(2))")?, a_and_b_msp);
    assert_eq!(to_msp("((1))&((2))")?, a_and_b_msp);
    assert_eq!(to_msp("(((1))&((2)))")?, a_and_b_msp);

    // can be written let formula = a & (d | (b & c));
    let formula_str = "1 & (4 | (2 & 3))";
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    let msp = formula.to_msp()?;
    let msp_2 = Node::parse(formula_str)?.to_msp()?;

    assert_eq!(msp, msp_2);
    Ok(())
}

#[test]
fn test_equality() -> Result<(), FormatErr> {
    // can be written let formula = a & (d | (b & c));
    let formula_str = "1 & (4 | (2 & 3))";
    let other_formula = "1 & (4 | (2 & 3))";
    let another_formula_again = "1 & 2";
    let msp_1 = Node::parse(formula_str)?.to_msp()?;
    let msp_2 = Node::parse(other_formula)?.to_msp()?;
    let msp_3 = Node::parse(another_formula_again)?.to_msp()?;

    assert_eq!(msp_1, msp_2);
    assert_ne!(msp_2, msp_3);

    assert_ne!(Node::parse("1&2")?.to_msp()?, Node::parse("1|2")?.to_msp()?);

    Ok(())
}

#[test]
fn parsing_multi() -> Result<(), FormatErr> {
    Node::parse("1 & (4 | (2 & 3))")?;
    Node::parse("(1 & 2) | (2 & 3)")?;
    Node::parse("1 | 2")?;
    Node::parse("1 | (2 & 3)")?;
    Node::parse("(1 & 2) | 3")?;
    Ok(())
}

#[test]
fn parsing_fail() {
    // extra right parens
    assert!(Node::parse("1 & 4 | (2 & 3))").is_err());
    // missing middle operator
    assert!(Node::parse("(1 & 2)  (2 & 3)").is_err());
    // missing right operand
    assert!(Node::parse("1 | ").is_err());
    // missing left parens (before '2')
    assert!(Node::parse("1 | 2 & 3)").is_err());
}

#[test]
#[should_panic]
fn parsing_with_failures() {
    let formula_str = "1 && (4 | (2 & 3))";
    Node::parse(formula_str).unwrap();
}

#[test]
#[should_panic]
fn parsing_with_bad_formula() {
    let formula_str = "1 && ((4 | 2 & 3)))";
    Node::parse(formula_str).unwrap();
}

#[test]
fn msp_to_matrix() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));
    // can be written let formula = a & (d | (b & c));
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    println!("formula: {}", formula);
    let msp = formula.to_msp()?;
    println!("msp: {}", msp);
    Ok(())
}

#[test]
fn msp_as_bytes() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));
    // can be written let formula = a & (d | (b & c));
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    println!("formula: {}", formula);
    let msp = formula.to_msp()?;
    println!("msp: {}", msp);
    //let msp_2 = msp.as_bytes()?;
    let msp_2 = MonotoneSpanProgram::<i32>::from_bytes(&msp.as_bytes()?)?;
    assert_eq!(msp.nb_row, msp_2.nb_row);
    assert_eq!(msp.nb_col, msp_2.nb_col);
    assert_eq!(msp.row_to_attr, msp_2.row_to_attr);
    assert_eq!(msp.matrix, msp_2.matrix);
    assert_eq!(msp.attr_to_row, msp_2.attr_to_row);
    Ok(())
}

#[test]
#[should_panic]
fn leaf_already_inserted() {
    Node::parse("3 & (4 | (2 & 3))").unwrap().to_msp().unwrap();
}
