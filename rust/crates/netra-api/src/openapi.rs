use utoipa::OpenApi;

use crate::errors::{ErrorDetail, ErrorEnvelope, MetaEnvelope, SuccessEnvelope};
use crate::routes::diagnostics::DiagnosticsData;
use crate::routes::health::HealthData;
use crate::routes::status::StatusData;
use crate::routes::storage::{
    StorageCheckData, StorageCheckQuery, StorageRecordCounts, StorageStatusData,
};
use crate::routes::version::VersionData;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health::get_health,
        crate::routes::version::get_version,
        crate::routes::status::get_status,
        crate::routes::diagnostics::get_diagnostics,
        crate::routes::storage::get_storage_status,
        crate::routes::storage::get_storage_check,
    ),
    components(
        schemas(
            HealthData,
            VersionData,
            StatusData,
            DiagnosticsData,
            StorageStatusData,
            StorageRecordCounts,
            StorageCheckQuery,
            StorageCheckData,
            ErrorDetail,
            ErrorEnvelope,
            MetaEnvelope,
            SuccessEnvelope<HealthData>,
            SuccessEnvelope<VersionData>,
            SuccessEnvelope<StatusData>,
            SuccessEnvelope<DiagnosticsData>,
            SuccessEnvelope<StorageStatusData>,
            SuccessEnvelope<StorageCheckData>,
        )
    ),
    tags(
        (name = "system", description = "System and runtime inspection endpoints"),
        (name = "storage", description = "Embedded SQLite storage diagnostics and integrity endpoints")
    ),
    info(
        title = "NETRA Control-Plane REST API",
        version = "1.0.0",
        description = "Control-Plane REST API Gateway and Contract Layer for NETRA endpoint runtime."
    )
)]
pub struct ApiDoc;
