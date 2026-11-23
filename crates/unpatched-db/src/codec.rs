//! Text forms of small enums stored in columns.

use unpatched_core::{SourceId, SsvcExploitation};

pub(crate) fn source_to_str(s: SourceId) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(crate) fn source_from_str(s: &str) -> Option<SourceId> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
}

pub(crate) fn ssvc_to_str(e: SsvcExploitation) -> &'static str {
    match e {
        SsvcExploitation::None => "none",
        SsvcExploitation::Poc => "poc",
        SsvcExploitation::Active => "active",
    }
}

pub(crate) fn ssvc_from_str(s: &str) -> Option<SsvcExploitation> {
    match s {
        "none" => Some(SsvcExploitation::None),
        "poc" => Some(SsvcExploitation::Poc),
        "active" => Some(SsvcExploitation::Active),
        _ => None,
    }
}
