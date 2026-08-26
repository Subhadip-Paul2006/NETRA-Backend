//! # CLI Argument Parsing & Command Hierarchy Tests (`parsing_tests.rs`)

use clap::Parser;
use netra_cli::cli::{CliArgs, Commands, StorageSubcommand};

#[test]
fn test_parse_default_command() {
    let args = CliArgs::try_parse_from(["netra"]).unwrap();
    assert!(args.command.is_none());
    assert!(!args.json);
    assert!(!args.quiet);
    assert!(!args.no_color);
    assert!(args.config.is_none());
}

#[test]
fn test_parse_status_command() {
    let args = CliArgs::try_parse_from(["netra", "status"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Status)));
}

#[test]
fn test_parse_diagnostics_command() {
    let args = CliArgs::try_parse_from(["netra", "diagnostics"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Diagnostics)));
}

#[test]
fn test_parse_version_command() {
    let args = CliArgs::try_parse_from(["netra", "version"]).unwrap();
    assert!(matches!(args.command, Some(Commands::Version)));
}

#[test]
fn test_parse_storage_subcommands() {
    // 1. storage status
    let args = CliArgs::try_parse_from(["netra", "storage", "status"]).unwrap();
    if let Some(Commands::Storage(s)) = args.command {
        assert!(matches!(s.action, StorageSubcommand::Status));
    } else {
        panic!("Expected storage status subcommand");
    }

    // 2. storage check (default)
    let args = CliArgs::try_parse_from(["netra", "storage", "check"]).unwrap();
    if let Some(Commands::Storage(s)) = args.command {
        if let StorageSubcommand::Check(chk) = s.action {
            assert!(!chk.deep);
        } else {
            panic!("Expected storage check");
        }
    } else {
        panic!("Expected storage command");
    }

    // 3. storage check --deep
    let args = CliArgs::try_parse_from(["netra", "storage", "check", "--deep"]).unwrap();
    if let Some(Commands::Storage(s)) = args.command {
        if let StorageSubcommand::Check(chk) = s.action {
            assert!(chk.deep);
        } else {
            panic!("Expected storage check");
        }
    } else {
        panic!("Expected storage command");
    }

    // 4. storage recover (default)
    let args = CliArgs::try_parse_from(["netra", "storage", "recover"]).unwrap();
    if let Some(Commands::Storage(s)) = args.command {
        if let StorageSubcommand::Recover(rec) = s.action {
            assert!(!rec.force_reinit);
        } else {
            panic!("Expected storage recover");
        }
    } else {
        panic!("Expected storage command");
    }

    // 5. storage recover --force-reinit
    let args = CliArgs::try_parse_from(["netra", "storage", "recover", "--force-reinit"]).unwrap();
    if let Some(Commands::Storage(s)) = args.command {
        if let StorageSubcommand::Recover(rec) = s.action {
            assert!(rec.force_reinit);
        } else {
            panic!("Expected storage recover");
        }
    } else {
        panic!("Expected storage command");
    }
}

#[test]
fn test_parse_global_flags() {
    let args = CliArgs::try_parse_from([
        "netra",
        "--json",
        "--quiet",
        "--no-color",
        "--config",
        "/custom/netra.toml",
        "storage",
        "status",
    ])
    .unwrap();

    assert!(args.json);
    assert!(args.quiet);
    assert!(args.no_color);
    assert_eq!(
        args.config.unwrap(),
        std::path::PathBuf::from("/custom/netra.toml")
    );
    assert!(matches!(
        args.command,
        Some(Commands::Storage(ref s)) if matches!(s.action, StorageSubcommand::Status)
    ));
}

#[test]
fn test_parse_invalid_command_rejected() {
    let result = CliArgs::try_parse_from(["netra", "invalid_subcommand"]);
    assert!(result.is_err());
}

#[test]
fn test_parse_unknown_flag_rejected() {
    let result = CliArgs::try_parse_from(["netra", "--unknown-flag"]);
    assert!(result.is_err());
}
