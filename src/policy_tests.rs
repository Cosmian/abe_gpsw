use super::{AccessPolicy, Policy};
use crate::policy::{ap, attr};

#[test]
fn policy_group() -> eyre::Result<()> {
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

// #[test]
// fn partialeq_access_policy() {
//     let access_policy_1 = (ap("Countries", "FR") | ap("Countries", "EN") |
// ap("Countries", "DE"))         & ap("Levels", "Sec_level_1");
//     let access_policy_2 = (ap("Countries", "EN") | ap("Countries", "DE") |
// ap("Countries", "FR"))         & ap("Levels", "Sec_level_1");
//     // let f = access_policy_1.flatten_or();
//     // let g = access_policy_2.flatten_or();
//     // let r = f == g;
//     assert_eq!(access_policy_1, access_policy_2);
// }

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
    assert!(attributes.contains("MKG"));
    let attribute_to_int = policy_group.attribute_to_int;
    let dpt_hr = attribute_to_int
        .get(&attr("Department", "HR"))
        .ok_or("There should be a Department::HR")
        .unwrap();
    assert_eq!(vec![10, 6], dpt_hr.clone().into_vec());
}
