use zcash_template_provider::template::{TemplateProvider, TemplateProviderConfig};

#[tokio::test]
async fn test_template_provider_creation() {
    let config = TemplateProviderConfig {
        zebra_url: "http://127.0.0.1:8232".to_string(),
        submit_url: None,
        poll_interval_ms: 1000,
    };

    let provider = TemplateProvider::new(config);
    assert!(provider.is_ok());
}
