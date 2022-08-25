use std::convert::TryFrom;

use crate::{core::msp::policy_to_msp, error::FormatErr};

use abe_policy::{AccessPolicy, Attribute, Attributes, Policy, PolicyAxis};

#[test]
fn policy_group() -> Result<(), FormatErr> {
    let mut policy_group = Policy::new(1000);
    policy_group.add_axis(&PolicyAxis::new(
        "Security Level",
        &["level 1", "level 2", "level 3", "level 4", "level 5"],
        true,
    ))?;
    policy_group.add_axis(&PolicyAxis::new(
        "Department",
        &["R&D", "HR", "MKG", "fin"],
        false,
    ))?;
    let json = serde_json::to_string(&policy_group).unwrap();
    let _pol_acc: AccessPolicy = AccessPolicy::new("Security Level", "level 1")
        & (AccessPolicy::new("Department", "HR") | AccessPolicy::new("Department", "R&D"));
    // deserialization
    let _policy_group_: Policy = serde_json::from_str(&json).unwrap();
    // assert_eq!(policy_group, policy_group_);
    Ok(())
}

#[test]
fn attribute_parser() {
    let attribute = Attribute::from(("Security Level", "level 1"));
    Attribute::try_from(attribute.to_string().as_str()).unwrap();

    assert!(Attribute::try_from("").is_err());
    assert!(Attribute::try_from("A:B").is_err());
    assert!(Attribute::try_from("::").is_err());
    assert!(Attribute::try_from("::::").is_err());

    let attribute2 = Attribute::new("Security Level", "level 1");
    assert_eq!(
        Attribute::try_from(" Security Level::level 1  ").unwrap(),
        attribute2
    );
}

#[test]
fn attributes_parser() {
    let attributes = Attributes::try_from(" Security Level::level 1 ,    Department::HR ").unwrap();

    assert_eq!(
        attributes,
        Attributes::from(vec![
            Attribute::try_from("Security Level::level 1").unwrap(),
            Attribute::try_from("Department::HR").unwrap()
        ])
    );
}

#[test]
fn partialeq_access_policy() {
    let fr = AccessPolicy::new("Countries", "FR"); //1
    let en = AccessPolicy::new("Countries", "EN"); //2
    let de = AccessPolicy::new("Countries", "DE"); //3
    let au = AccessPolicy::new("Countries", "AU"); //4
    let sec_level_1 = AccessPolicy::new("Levels", "Sec_level_1");
    let access_policy_1 = (fr.clone() | en.clone() | de.clone()) & sec_level_1.clone();
    let access_policy_2 = (en.clone() | de.clone() | fr.clone()) & sec_level_1.clone();
    let access_policy_3 = (de.clone() | fr.clone() | en.clone()) & sec_level_1.clone();

    // We must have the equality
    assert_eq!(access_policy_1, access_policy_2);
    assert_eq!(access_policy_1, access_policy_3);

    // Those 2 next access policies have the same (integer) value but different
    // attributes. So they cannot be equal
    let access_policy_4 =
        (fr.clone() | en.clone() | de.clone() | au.clone() | fr.clone() | de.clone())
            & sec_level_1.clone();
    let access_policy_5 = (fr.clone() | en | de.clone() | au.clone() | au) & sec_level_1;
    assert_ne!(access_policy_4, access_policy_5);

    // Make sure those 2 policies are not equivalent
    let access_policy_fr_de = fr & de.clone(); //to u32 = 1*2
    let access_policy_de = de; // to u32 = 2
    assert_ne!(access_policy_fr_de, access_policy_de);
}

#[test]
fn policy_group_from_java() {
    let json = r#"{"last_attribute_value":10,"max_attribute_creations":1000,"axes":{"Department":[["HR","MKG","R&D","fin"],false],"Security Level":[["level 1","level 2","level 3","level 4","level 5"],true]},"attribute_to_int":{"Security Level::level 5":[5],"Security Level::level 3":[3],"Department::HR":[10,6],"Department::R&D":[8],"Security Level::level 4":[4],"Security Level::level 1":[1],"Department::MKG":[7],"Security Level::level 2":[2],"Department::fin":[9]}}"#;
    let policy_group: Policy = serde_json::from_str(json).unwrap();
    assert_eq!(10, policy_group.last_attribute_value);
    assert_eq!(1000, policy_group.max_attribute_creations);
    let (attributes, hierarchical) = policy_group
        .axes
        .get("Department")
        .ok_or("There should be a department")
        .unwrap();
    assert!(!*hierarchical);
    assert!(attributes.contains(&"MKG".to_string()));
    let attribute_to_int = policy_group.attribute_to_int;
    let dpt_hr = attribute_to_int
        .get(&Attribute::new("Department", "HR"))
        .ok_or("There should be a Department::HR")
        .unwrap();
    assert_eq!(vec![10, 6], dpt_hr.clone().into_vec());
}

#[test]
fn parse_boolean_expression() {
    let access_policy = AccessPolicy::from_boolean_expression(
        "(Department::HR || Department::R&D) && Level::level_2",
    )
    .unwrap();
    let expected_ap = (AccessPolicy::new("Department", "HR")
        | AccessPolicy::new("Department", "R&D"))
        & AccessPolicy::new("Level", "level_2");
    assert_eq!(expected_ap, access_policy);

    let access_policy = AccessPolicy::from_boolean_expression(
        "Level::level_2&&(Department::HR || Department::R&D) ",
    )
    .unwrap();
    assert_eq!(expected_ap, access_policy);

    let access_policy =
        AccessPolicy::from_boolean_expression("(((Department::HR))) && Level::level_2").unwrap();
    let expected_ap =
        (AccessPolicy::new("Department", "HR")) & AccessPolicy::new("Level", "level_2");
    assert_eq!(expected_ap, access_policy);

    let access_policy = AccessPolicy::from_boolean_expression("(((Department::HR)))").unwrap();
    let expected_ap = AccessPolicy::new("Department", "HR");
    assert_eq!(expected_ap, access_policy);

    assert!(AccessPolicy::from_boolean_expression("Department:HR").is_err());
    assert!(AccessPolicy::from_boolean_expression("Department::HR&&").is_err());
    assert!(AccessPolicy::from_boolean_expression("Department::HR||::").is_err());
    assert!(AccessPolicy::from_boolean_expression("::").is_err());
}

#[test]
fn parse_boolean_expression_additional_tests() {
    let expected_ap =
        (AccessPolicy::new("X", "A") | AccessPolicy::new("X", "B")) & AccessPolicy::new("Y", "111");

    let access_policy = AccessPolicy::from_boolean_expression("(X::A || X::B) && Y::111").unwrap();
    assert_eq!(expected_ap, access_policy);

    let access_policy =
        AccessPolicy::from_boolean_expression("  (  X  ::  A  ||   X  ::  B  )  && Y  ::  111  ")
            .unwrap();
    assert_eq!(expected_ap, access_policy);

    let access_policy = AccessPolicy::from_boolean_expression(
        "( with spaces::a lot of spaces & || really a lot::really ? ) &&   why not :: here too",
    )
    .unwrap();
    let expected_ap = (AccessPolicy::new("with spaces", "a lot of spaces &")
        | AccessPolicy::new("really a lot", "really ?"))
        & AccessPolicy::new("why not", "here too");
    assert_eq!(expected_ap, access_policy);
}

#[test]
fn verify_access_policy() {
    let mut policy = Policy::new(1000);
    policy
        .add_axis(&PolicyAxis::new(
            "Level",
            &["level 1", "level 2", "level 3", "level 4", "level 5"],
            true,
        ))
        .unwrap();

    policy
        .add_axis(&PolicyAxis::new(
            "Department",
            &["R&D", "HR", "MKG", "fin"],
            false,
        ))
        .unwrap();
    let access_policy = AccessPolicy::from_boolean_expression(
        "(Department::HR || Department::R&D) && Level::level 2",
    )
    .unwrap();

    policy_to_msp(&policy, &access_policy).unwrap();

    let access_policy = AccessPolicy::from_boolean_expression(
        "(Axis_Name_Not_Existing_in_Policy::HR || Department::R&D) && Level::level 2",
    )
    .unwrap();
    assert!(policy_to_msp(&policy, &access_policy).is_err());

    let access_policy = AccessPolicy::from_boolean_expression(
        "(Department::Attribute_Value_Not_Existing_in_Policy || Department::R&D) && Level::level 2",
    )
    .unwrap();
    assert!(policy_to_msp(&policy, &access_policy).is_err());
}
