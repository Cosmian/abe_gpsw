use crate::{
    core::policy::{ap, attr, AccessPolicy, Policy},
    error::FormatErr,
};

#[test]
fn policy_group() -> Result<(), FormatErr> {
    let policy_group = Policy::new(1000)
        .add_axis(
            "Security Level",
            &["level 1", "level 2", "level 3", "level 4", "level 5"],
            true,
        )?
        .add_axis("Department", &["R&D", "HR", "MKG", "fin"], false)?;
    let json = serde_json::to_string(&policy_group).unwrap();
    println!("{}", &json);
    let _pol_acc: AccessPolicy =
        ap("Security Level", "level 1") & (ap("Department", "HR") | ap("Department", "R&D"));
    // deserialization
    let _policy_group_: Policy = serde_json::from_str(&json).unwrap();
    // assert_eq!(policy_group, policy_group_);
    Ok(())
}

#[test]
fn partialeq_access_policy() {
    let fr = ap("Countries", "FR"); //1
    let en = ap("Countries", "EN"); //2
    let de = ap("Countries", "DE"); //3
    let au = ap("Countries", "AU"); //4
    let sec_level_1 = ap("Levels", "Sec_level_1");
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
    let json = r#"{"last_attribute":10,"max_attribute":1000,"store":{"Department":[["HR","MKG","R&D","fin"],false],"Security Level":[["level 1","level 2","level 3","level 4","level 5"],true]},"attribute_to_int":{"Security Level::level 5":[5],"Security Level::level 3":[3],"Department::HR":[10,6],"Department::R&D":[8],"Security Level::level 4":[4],"Security Level::level 1":[1],"Department::MKG":[7],"Security Level::level 2":[2],"Department::fin":[9]}}"#;
    let policy_group: Policy = serde_json::from_str(json).unwrap();
    assert_eq!(10, policy_group.last_attribute);
    assert_eq!(1000, policy_group.max_attribute);
    let (attributes, hierarchical) = policy_group
        .store
        .get("Department")
        .ok_or("There should be a department")
        .unwrap();
    assert!(!*hierarchical);
    assert!(attributes.contains(&"MKG".to_string()));
    let attribute_to_int = policy_group.attribute_to_int;
    let dpt_hr = attribute_to_int
        .get(&attr("Department", "HR"))
        .ok_or("There should be a Department::HR")
        .unwrap();
    assert_eq!(vec![10, 6], dpt_hr.clone().into_vec());
}