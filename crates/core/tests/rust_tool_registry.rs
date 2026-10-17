use serde_json::json;

#[test]
fn the_picker_query_asks_for_recency() {
    let args = serde_json::to_value(noted::tools::SearchNotesArgs::recent()).unwrap();
    assert_eq!(args["mode"], json!("path"));
    assert_eq!(args["sort"], json!("modified"));
}
