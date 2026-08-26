#[cfg(windows)]
use netra_cli::cli::{EnrollArgs, RotateArgs};
use netra_cli::cli::{IdentityArgs, IdentitySubcommand};
#[cfg(windows)]
use netra_cli::commands::identity::execute_enroll;
use netra_cli::commands::identity::execute_identity;
use netra_cli::errors::ExitCode;
use netra_cli::output::OutputPresenter;
use netra_core::config::NetraConfig;
use netra_core::storage::DatabaseEngine;

#[tokio::test]
async fn test_identity_cli_enroll_and_status_flow() {
    let engine = DatabaseEngine::in_memory().unwrap();
    let config = NetraConfig::default();
    let presenter = OutputPresenter::new(true, true, true); // JSON mode

    // 1. Initial status on unenrolled database
    let status_args = IdentityArgs {
        action: Some(IdentitySubcommand::Status),
    };
    let exit1 = execute_identity(&status_args, &config, Some(&engine), &presenter)
        .await
        .unwrap();
    assert_eq!(exit1, ExitCode::Success);

    #[cfg(windows)]
    {
        // 2. Perform enrollment
        let enroll_args = EnrollArgs {
            token: "enroll_token_test_12345".to_string(),
            gateway: "wss://127.0.0.1:8443/api/v1/agent/stream".to_string(),
            #[cfg(feature = "insecure-dev-keystore")]
            insecure_dev_keystore: false,
        };
        let exit2 = execute_enroll(&enroll_args, &config, Some(&engine), &presenter)
            .await
            .unwrap();
        assert_eq!(exit2, ExitCode::Success);

        // 3. Status on enrolled database
        let exit3 = execute_identity(&status_args, &config, Some(&engine), &presenter)
            .await
            .unwrap();
        assert_eq!(exit3, ExitCode::Success);

        // 4. Key rotation
        let rotate_args = IdentityArgs {
            action: Some(IdentitySubcommand::Rotate(RotateArgs { emergency: false })),
        };
        let exit4 = execute_identity(&rotate_args, &config, Some(&engine), &presenter)
            .await
            .unwrap();
        assert_eq!(exit4, ExitCode::Success);
    }
}
