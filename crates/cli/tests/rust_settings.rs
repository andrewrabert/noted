use std::path::Path;

use noted_cli::settings::{Layer, Location, Settings, Variable};

const EVERY: &[Variable] = &[
    Variable::AdminSocket,
    Variable::AuthDb,
    Variable::DefaultTtl,
    Variable::Dir,
    Variable::Editor,
    Variable::EnvFile,
    Variable::Host,
    Variable::HostsFile,
    Variable::LogFile,
    Variable::LogLevel,
    Variable::Policy,
    Variable::Port,
    Variable::PublicUrl,
    Variable::Scope,
    Variable::Source,
    Variable::Token,
    Variable::Url,
    Variable::Visual,
];

/// The environment layer, with the process's own bindings cleared so a test
/// says everything that layer carries.
fn environment(bindings: &[(Variable, &str)]) -> Layer {
    let mut layer = Layer::environment();
    for var in EVERY {
        layer.set(*var, Some(""));
    }
    bind(&mut layer, bindings);
    layer
}

fn flags(bindings: &[(Variable, &str)]) -> Layer {
    let mut layer = Layer::flags();
    bind(&mut layer, bindings);
    layer
}

fn bind(layer: &mut Layer, bindings: &[(Variable, &str)]) {
    for (var, value) in bindings {
        layer.set(*var, Some(value));
    }
}

fn file(text: &str) -> Layer {
    Layer::file(Path::new("/etc/noted.env"), text).unwrap()
}

fn refusal(layers: Vec<Layer>) -> String {
    match Settings::resolve(layers) {
        Ok(_) => panic!("resolved settings that must be refused"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn a_flag_beats_the_environment_and_the_environment_beats_the_file() {
    let layered = |layers| Settings::resolve(layers).unwrap();

    let all = layered(vec![
        flags(&[(Variable::Source, "from-flag")]),
        environment(&[(Variable::Source, "from-env")]),
        file("NOTED_SOURCE=from-file\n"),
    ]);
    assert_eq!(all.get(Variable::Source), Some("from-flag"));

    let below = layered(vec![
        flags(&[]),
        environment(&[(Variable::Source, "from-env")]),
        file("NOTED_SOURCE=from-file\n"),
    ]);
    assert_eq!(below.get(Variable::Source), Some("from-env"));

    let bottom = layered(vec![
        flags(&[]),
        environment(&[]),
        file("NOTED_SOURCE=from-file\n"),
    ]);
    assert_eq!(bottom.get(Variable::Source), Some("from-file"));
}

#[test]
fn both_location_spellings_in_one_layer_are_refused_naming_both_and_the_layer() {
    let from_flags = refusal(vec![flags(&[
        (Variable::Dir, "/notes"),
        (Variable::Url, "https://notes.example"),
    ])]);
    assert!(from_flags.contains("NOTED_DIR"), "{from_flags}");
    assert!(from_flags.contains("NOTED_URL"), "{from_flags}");
    assert!(from_flags.contains("the command line"), "{from_flags}");

    let from_env = refusal(vec![environment(&[
        (Variable::Dir, "/notes"),
        (Variable::Url, "https://notes.example"),
    ])]);
    assert!(from_env.contains("the environment"), "{from_env}");
}

#[test]
fn a_file_naming_both_spellings_is_refused_though_a_flag_sets_one() {
    let from_file = refusal(vec![
        flags(&[(Variable::Dir, "/notes")]),
        environment(&[]),
        file("NOTED_DIR=/other\nNOTED_URL=https://notes.example\n"),
    ]);
    assert!(from_file.contains("NOTED_DIR"), "{from_file}");
    assert!(from_file.contains("NOTED_URL"), "{from_file}");
    assert!(from_file.contains("/etc/noted.env"), "{from_file}");
}

#[test]
fn a_nearer_location_discards_the_other_spelling_from_every_layer_below() {
    let settings = Settings::resolve(vec![
        flags(&[(Variable::Dir, "/notes")]),
        environment(&[(Variable::Url, "https://notes.example")]),
        file("NOTED_URL=https://stale.example\n"),
    ])
    .unwrap();
    assert_eq!(settings.get(Variable::Dir), Some("/notes"));
    assert_eq!(settings.get(Variable::Url), None);
    assert!(matches!(settings.location(), Some(Location::Dir(dir)) if dir == "/notes"));

    let url_wins = Settings::resolve(vec![
        flags(&[]),
        environment(&[(Variable::Url, "https://notes.example")]),
        file("NOTED_DIR=/stale\n"),
    ])
    .unwrap();
    assert_eq!(url_wins.get(Variable::Dir), None);
    assert_eq!(url_wins.get(Variable::Url), Some("https://notes.example"));
    assert!(
        matches!(url_wins.location(), Some(Location::Url(url)) if url == "https://notes.example")
    );
}

#[test]
fn scope_and_policy_survive_a_location_override() {
    let settings = Settings::resolve(vec![
        flags(&[(Variable::Dir, "/notes")]),
        environment(&[
            (Variable::Url, "https://notes.example"),
            (Variable::Scope, "dev"),
        ]),
        file("NOTED_POLICY=read\n"),
    ])
    .unwrap();
    assert!(matches!(settings.location(), Some(Location::Dir(dir)) if dir == "/notes"));
    assert_eq!(settings.get(Variable::Scope), Some("dev"));
    assert_eq!(settings.get(Variable::Policy), Some("read"));
}

#[test]
fn every_other_variable_layers_on_its_own() {
    let settings = Settings::resolve(vec![
        flags(&[(Variable::Token, "from-flag")]),
        environment(&[(Variable::Host, "from-env")]),
        file("NOTED_PORT=8080\nNOTED_LOG_LEVEL=debug\n"),
    ])
    .unwrap();
    assert_eq!(settings.get(Variable::Token), Some("from-flag"));
    assert_eq!(settings.get(Variable::Host), Some("from-env"));
    assert_eq!(settings.get(Variable::Port), Some("8080"));
    assert_eq!(settings.get(Variable::LogLevel), Some("debug"));
    assert_eq!(settings.get(Variable::AdminSocket), None);
}

#[test]
fn a_binding_naming_no_setting_is_ignored() {
    assert!(Variable::named("ALPHA").is_none());

    let settings = Settings::resolve(vec![file(
        "ALPHA=/notes\nNOTED_SOURCE=repo\nNOTED_NOT_A_SETTING=1\n",
    )])
    .unwrap();
    assert_eq!(settings.get(Variable::Source), Some("repo"));
    assert_eq!(settings.get(Variable::Dir), None);
    assert!(settings.location().is_none());
}
