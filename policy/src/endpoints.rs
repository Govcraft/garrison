//! Which of this machine's configured providers the organization approved.
//!
//! "Which models are we allowed to send code to, and on whose signature" is
//! one of the four questions Garrison's README puts to an auditor, and the
//! answer has to come from the plane rather than from the file on the
//! workstation. `acton-ai.toml` says what this daemon *can* reach; the
//! bundle's `ModelEndpoint` rows say what it *may*. This is the intersection.
//!
//! # Matching is by what the request will look like, not by name
//!
//! Two operators will not spell an endpoint's name the same way, so names are
//! not compared. What is compared is the three things that determine where a
//! prompt actually goes: the provider type, the model, and the base URL. An
//! endpoint that matches on all three is the same endpoint however either
//! side named it.

use crate::bundle::{Bundle, ModelEndpoint};
use crate::checksum::normalize_base_url;

/// One provider as `acton-ai.toml` configured it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfiguredProvider {
    /// The key under `[providers.…]`, which is what `default_provider` names.
    pub name: String,
    /// `anthropic`, `openai`, `ollama`, `kimi`.
    pub provider_type: String,
    /// The model it is configured to use.
    pub model: String,
    /// Its base URL, when the provider takes one.
    pub base_url: Option<String>,
}

/// The names of the configured providers an approved endpoint covers.
///
/// Pure. The order follows `configured`, so `_garrison/status` lists them the
/// way the operator's own file does.
#[must_use]
pub fn approved_providers(bundle: &Bundle, configured: &[ConfiguredProvider]) -> Vec<String> {
    configured
        .iter()
        .filter(|provider| {
            bundle
                .endpoints
                .iter()
                .any(|endpoint| covers(endpoint, provider))
        })
        .map(|provider| provider.name.clone())
        .collect()
}

/// Whether one approved endpoint is the place this provider would send to.
#[must_use]
pub fn covers(endpoint: &ModelEndpoint, provider: &ConfiguredProvider) -> bool {
    if !endpoint.is_usable() {
        return false;
    }
    if !endpoint.model.eq_ignore_ascii_case(&provider.model) {
        return false;
    }

    let endpoint_url = normalize_base_url(endpoint.base_url.as_deref());
    let provider_url = normalize_base_url(provider.base_url.as_deref());
    if !endpoint_url.eq_ignore_ascii_case(&provider_url) {
        return false;
    }

    if endpoint
        .provider_type
        .eq_ignore_ascii_case(&provider.provider_type)
    {
        return true;
    }

    // `openai_compatible` is the plane's word for "an OpenAI-shaped API that
    // is not OpenAI". It stands in for acton-ai's `openai` only when both
    // sides name the same base URL, because an endpoint row with no URL and a
    // provider with no URL are both plain api.openai.com, and approving one
    // must not silently approve the other.
    endpoint
        .provider_type
        .eq_ignore_ascii_case("openai_compatible")
        && provider.provider_type.eq_ignore_ascii_case("openai")
        && endpoint_url.is_some()
}

/// Compares two optional URLs without regard to case in the host.
trait CaseInsensitiveUrl {
    fn eq_ignore_ascii_case(&self, other: &Self) -> bool;
}

impl CaseInsensitiveUrl for Option<&str> {
    fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        match (self, other) {
            (None, None) => true,
            (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::Bundle;

    fn endpoint(provider_type: &str, model: &str, base_url: Option<&str>) -> ModelEndpoint {
        ModelEndpoint {
            id: "modelendpoint_01".into(),
            name: "approved".into(),
            provider_type: provider_type.into(),
            model: model.into(),
            base_url: base_url.map(str::to_string),
            authorization: "ato".into(),
            status: "approved".into(),
        }
    }

    fn provider(
        name: &str,
        provider_type: &str,
        model: &str,
        base_url: Option<&str>,
    ) -> ConfiguredProvider {
        ConfiguredProvider {
            name: name.into(),
            provider_type: provider_type.into(),
            model: model.into(),
            base_url: base_url.map(str::to_string),
        }
    }

    fn with(endpoints: Vec<ModelEndpoint>) -> Bundle {
        Bundle {
            endpoints,
            ..Bundle::default()
        }
    }

    #[test]
    fn a_provider_matching_an_approved_endpoint_is_approved() {
        let bundle = with(vec![endpoint(
            "ollama",
            "qwen3.8",
            Some("http://127.0.0.1:11434/v1"),
        )]);
        let configured = [provider(
            "ollama",
            "ollama",
            "qwen3.8",
            Some("http://127.0.0.1:11434/v1/"),
        )];

        assert_eq!(approved_providers(&bundle, &configured), ["ollama"]);
    }

    #[test]
    fn a_provider_the_bundle_never_names_is_not_approved() {
        let bundle = with(vec![endpoint("ollama", "qwen3.8", None)]);
        let configured = [provider("claude", "anthropic", "claude-sonnet-5", None)];

        assert!(approved_providers(&bundle, &configured).is_empty());
    }

    #[test]
    fn a_different_model_on_the_same_endpoint_is_a_different_endpoint() {
        let bundle = with(vec![endpoint("ollama", "qwen3.8", None)]);
        let configured = [provider("ollama", "ollama", "llama3.3", None)];

        assert!(approved_providers(&bundle, &configured).is_empty());
    }

    #[test]
    fn a_suspended_or_denied_endpoint_approves_nothing() {
        for (field, value) in [("status", "suspended"), ("authorization", "denied")] {
            let mut row = endpoint("ollama", "qwen3.8", None);
            match field {
                "status" => row.status = value.into(),
                _ => row.authorization = value.into(),
            }
            let bundle = with(vec![row]);
            let configured = [provider("ollama", "ollama", "qwen3.8", None)];

            assert!(
                approved_providers(&bundle, &configured).is_empty(),
                "{field} = {value}"
            );
        }
    }

    #[test]
    fn a_url_that_differs_is_a_different_place_to_send_code() {
        let bundle = with(vec![endpoint(
            "ollama",
            "qwen3.8",
            Some("http://on-prem:11434/v1"),
        )]);
        let configured = [provider(
            "ollama",
            "ollama",
            "qwen3.8",
            Some("http://elsewhere/v1"),
        )];

        assert!(approved_providers(&bundle, &configured).is_empty());
    }

    #[test]
    fn an_endpoint_with_no_url_does_not_approve_a_provider_that_has_one() {
        let bundle = with(vec![endpoint("openai", "gpt-5", None)]);
        let configured = [provider(
            "proxy",
            "openai",
            "gpt-5",
            Some("http://proxy/v1"),
        )];

        assert!(approved_providers(&bundle, &configured).is_empty());
    }

    #[test]
    fn openai_compatible_stands_in_for_openai_only_when_both_name_the_same_url() {
        let approved = with(vec![endpoint(
            "openai_compatible",
            "gpt-oss",
            Some("https://gateway.agency.gov/v1"),
        )]);
        let configured = [provider(
            "gateway",
            "openai",
            "gpt-oss",
            Some("https://gateway.agency.gov/v1"),
        )];
        assert_eq!(approved_providers(&approved, &configured), ["gateway"]);

        let urlless = with(vec![endpoint("openai_compatible", "gpt-oss", None)]);
        let plain = [provider("openai", "openai", "gpt-oss", None)];
        assert!(
            approved_providers(&urlless, &plain).is_empty(),
            "a URL-less compatible endpoint must not silently approve api.openai.com"
        );
    }

    #[test]
    fn approvals_are_listed_in_the_order_the_operators_own_file_lists_them() {
        let bundle = with(vec![
            endpoint("ollama", "qwen3.8", None),
            endpoint("anthropic", "claude-sonnet-5", None),
        ]);
        let configured = [
            provider("claude", "anthropic", "claude-sonnet-5", None),
            provider("local", "ollama", "qwen3.8", None),
        ];

        assert_eq!(
            approved_providers(&bundle, &configured),
            ["claude", "local"]
        );
    }
}
