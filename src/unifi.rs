use anyhow::{Result, anyhow};
use async_trait::async_trait;
use log::{debug, info};
use reqwest::{Client, Error, Url, header};
use serde::{Deserialize, Serialize};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait HttpClient: Send + Sync + 'static {
    async fn get(&self, url: Url) -> Result<reqwest::Response, reqwest::Error>;
    async fn post(
        &self,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, reqwest::Error>;
    async fn put(
        &self,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, reqwest::Error>;
    async fn delete(&self, url: Url) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl HttpClient for Client {
    async fn get(&self, url: Url) -> Result<reqwest::Response, reqwest::Error> {
        self.get(url).send().await
    }
    async fn post(
        &self,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut request = self.post(url);
        if let Some(b) = body {
            request = request.json(&b);
        }
        request.send().await
    }
    async fn put(
        &self,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut request = self.put(url);
        if let Some(b) = body {
            request = request.json(&b);
        }
        request.send().await
    }
    async fn delete(&self, url: Url) -> Result<reqwest::Response, reqwest::Error> {
        self.delete(url).send().await
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnifiApiResponse<T> {
    pub meta: UnifiApiMeta,
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnifiApiMeta {
    pub rc: String,
    // Add other meta fields if needed
}

// Check if UnifiApiMeta rc is "ok"
impl UnifiApiMeta {
    pub fn is_ok(&self) -> bool {
        self.rc == "ok"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortForwardRule {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub enabled: bool,
    #[serde(rename = "pfwd_interface")]
    pub pfwd_interface: String,
    #[serde(rename = "fwd")]
    pub fwd: String,
    #[serde(rename = "destination_ip")]
    pub destination_ip: Option<String>, // destination_ip is sometimes missing
    pub src: String,
    pub log: bool,
    #[serde(rename = "dst_port")]
    pub dst_port: serde_json::Value, // Can be string or number
    #[serde(rename = "fwd_port")]
    pub fwd_port: serde_json::Value, // Can be string or number
    pub proto: String,
    pub site_id: String,
}

impl PortForwardRule {
    pub async fn list(client: &UnifiClient) -> Result<Vec<PortForwardRule>> {
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/portforward",
            client.base_url, client.site_name
        );
        let url = Url::parse(&url_str)?;
        debug!("Getting port forward rules from '{}'", url);
        let response = client.client.get(url).await?.error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<Vec<PortForwardRule>>>()
            .await?;
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        debug!("Got {} port forward rules", api_response.data.len());
        Ok(api_response.data)
    }

    pub async fn create(&self, client: &UnifiClient) -> Result<PortForwardRule> {
        if client.dry_run {
            info!(
                "[dry-run] Skipping creation of port forward rule '{:?}'",
                self
            );
            return Ok(self.clone());
        }
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/portforward",
            client.base_url, client.site_name
        );
        let url = Url::parse(&url_str)?;
        info!("Creating port forward rule '{:?}'", self);
        let response = client
            .client
            .post(url, Some(serde_json::to_value(self)?))
            .await?
            .error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<Vec<PortForwardRule>>>()
            .await?;
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        info!("Created port forward rule '{:?}'", api_response.data[0]);
        Ok(api_response.data[0].clone())
    }

    pub async fn update(&self, client: &UnifiClient) -> Result<PortForwardRule> {
        if client.dry_run {
            info!(
                "[dry-run] Skipping update of port forward rule '{:?}'",
                self
            );
            return Ok(self.clone());
        }
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/portforward/{}",
            client.base_url,
            client.site_name,
            self.id.as_ref().unwrap()
        );
        let url = Url::parse(&url_str)?;
        info!("Updating port forward rule '{:?}'", self);
        let response = client
            .client
            .put(url, Some(serde_json::to_value(self)?))
            .await?
            .error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<Vec<PortForwardRule>>>()
            .await?;
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        info!("Updated port forward rule '{:?}'", api_response.data[0]);
        Ok(api_response.data[0].clone())
    }

    pub async fn delete(&self, client: &UnifiClient) -> Result<()> {
        if client.dry_run {
            info!(
                "[dry-run] Skipping deletion of port forward rule '{}'",
                self.id.as_ref().unwrap()
            );
            return Ok(());
        }
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/portforward/{}",
            client.base_url,
            client.site_name,
            self.id.as_ref().unwrap()
        );
        let url = Url::parse(&url_str)?;
        info!("Deleting port forward rule '{}'", self.id.as_ref().unwrap());
        let response = client.client.delete(url).await?.error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<serde_json::Value>>()
            .await?; // Assuming delete returns an empty data object or similar
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        info!("Deleted port forward rule '{}'", self.id.as_ref().unwrap());
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirewallGroup {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "group_type")]
    pub group_type: String,
    #[serde(rename = "group_members")]
    pub group_members: Vec<String>,
    pub site_id: String,
}

impl FirewallGroup {
    pub async fn list(client: &UnifiClient) -> Result<Vec<FirewallGroup>> {
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/firewallgroup",
            client.base_url, client.site_name
        );
        let url = Url::parse(&url_str)?;
        debug!("Getting firewall groups from '{}'", url);
        let response = client.client.get(url).await?.error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<Vec<FirewallGroup>>>()
            .await?;
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        debug!("Got {} firewall groups", api_response.data.len());
        Ok(api_response.data)
    }

    pub async fn create(&self, client: &UnifiClient) -> Result<FirewallGroup> {
        if client.dry_run {
            info!("[dry-run] Skipping creation of firewall group '{:?}'", self);
            return Ok(self.clone());
        }
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/firewallgroup",
            client.base_url, client.site_name
        );
        let url = Url::parse(&url_str)?;
        info!("Creating firewall group '{:?}'", self);
        let response = client
            .client
            .post(url, Some(serde_json::to_value(self)?))
            .await?
            .error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<Vec<FirewallGroup>>>()
            .await?;
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        info!("Created firewall group '{:?}'", api_response.data[0]);
        Ok(api_response.data[0].clone())
    }

    pub async fn update(&self, client: &UnifiClient) -> Result<FirewallGroup> {
        if client.dry_run {
            info!("[dry-run] Skipping update of firewall group '{:?}'", self);
            return Ok(self.clone());
        }
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/firewallgroup/{}",
            client.base_url,
            client.site_name,
            self.id.as_ref().unwrap()
        );
        let url = Url::parse(&url_str)?;
        info!("Updating firewall group '{:?}'", self);
        let response = client
            .client
            .put(url, Some(serde_json::to_value(self)?))
            .await?
            .error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<Vec<FirewallGroup>>>()
            .await?;
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        info!("Updated firewall group '{:?}'", api_response.data[0]);
        Ok(api_response.data[0].clone())
    }

    pub async fn delete(&self, client: &UnifiClient) -> Result<()> {
        if client.dry_run {
            info!(
                "[dry-run] Skipping deletion of firewall group '{}'",
                self.id.as_ref().unwrap()
            );
            return Ok(());
        }
        let url_str = format!(
            "https://{}/proxy/network/api/s/{}/rest/firewallgroup/{}",
            client.base_url,
            client.site_name,
            self.id.as_ref().unwrap()
        );
        let url = Url::parse(&url_str)?;
        info!("Deleting firewall group '{}'", self.id.as_ref().unwrap());
        let response = client.client.delete(url).await?.error_for_status()?;
        let api_response = response
            .json::<UnifiApiResponse<serde_json::Value>>()
            .await?; // Assuming delete returns an empty data object or similar
        if !api_response.meta.is_ok() {
            return Err(anyhow!("Unifi API error: {:?}", api_response.meta.rc));
        }
        info!("Deleted firewall group '{}'", self.id.as_ref().unwrap());
        Ok(())
    }
}

pub struct UnifiClient {
    client: Box<dyn HttpClient + Send + Sync>,
    base_url: String,
    pub site_name: String,
    pub dry_run: bool,
}

impl UnifiClient {
    pub async fn new(
        base_url: String,
        site_name: String,
        token: String,
        insecure: bool,
        dry_run: bool,
        http_client: Option<Box<dyn HttpClient + Send + Sync>>,
    ) -> Result<Self, Error> {
        let client = if let Some(client) = http_client {
            client
        } else {
            let mut headers = header::HeaderMap::new();
            headers.insert("X-API-KEY", header::HeaderValue::from_str(&token).unwrap());
            Box::new(Client::builder()
                .default_headers(headers)
                .danger_accept_invalid_certs(insecure)
                .build()?)
        };

        info!("Unifi client created for site '{}'", site_name);

        let unifi_client = UnifiClient {
            client,
            base_url,
            site_name,
            dry_run,
        };

        Ok(unifi_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http;
    use hyper;
    use mockall::*;
    use serde_json::json;
    use std::io::Cursor;
    use tokio;
    use tokio_util::io::ReaderStream;

    // Helper function to create a mock response
    fn mock_response(status: reqwest::StatusCode, body: serde_json::Value) -> reqwest::Response {
        let builder = http::Response::builder()
            .status(status)
            .header("content-type", "application/json");
        let body_bytes = body.to_string().into_bytes();
        let body_reader = ReaderStream::new(Cursor::new(body_bytes));
        let response = builder.body(hyper::Body::wrap_stream(body_reader)).unwrap();
        reqwest::Response::from(response)
    }

    #[tokio::test]
    async fn test_port_forward_rule_create() -> Result<()> {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client
            .expect_post()
            .once()
            .with(
                predicate::eq(
                    Url::parse("https://unifi/proxy/network/api/s/default/rest/portforward")
                        .unwrap(),
                ),
                predicate::eq(Some(json!({
                    "name": "test-rule",
                    "enabled": true,
                    "pfwd_interface": "wan",
                    "fwd": "192.168.1.100",
                    "destination_ip": "any",
                    "src": "any",
                    "log": false,
                    "dst_port": "80",
                    "fwd_port": "80",
                    "proto": "tcp",
                    "site_id": "default"
                }))),
            )
            .returning(|_, _| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({
                        "meta": { "rc": "ok" },
                        "data": [{
                            "_id": "new_id",
                            "name": "test-rule",
                            "enabled": true,
                            "pfwd_interface": "wan",
                            "fwd": "192.168.1.100",
                            "destination_ip": "any",
                            "src": "any",
                            "log": false,
                            "dst_port": "80",
                            "fwd_port": "80",
                            "proto": "tcp",
                            "site_id": "default"
                        }]
                    }),
                ))
            });

        let unifi_client = UnifiClient {
            client: Box::new(mock_http_client),
            base_url: "unifi".to_string(),
            site_name: "default".to_string(),
            dry_run: false,
        };

        let new_rule = PortForwardRule {
            id: None,
            name: "test-rule".to_string(),
            enabled: true,
            pfwd_interface: "wan".to_string(),
            fwd: "192.168.1.100".to_string(),
            destination_ip: Some("any".to_string()),
            src: "any".to_string(),
            log: false,
            dst_port: serde_json::Value::String("80".to_string()),
            fwd_port: serde_json::Value::String("80".to_string()),
            proto: "tcp".to_string(),
            site_id: "default".to_string(),
        };

        let created_rule = new_rule.create(&unifi_client).await?;
        assert_eq!(created_rule.id, Some("new_id".to_string()));
        assert_eq!(created_rule.name, "test-rule");

        Ok(())
    }

    #[tokio::test]
    async fn test_port_forward_rule_update() -> Result<()> {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client
            .expect_put()
            .once()
            .with(
                predicate::eq(
                    Url::parse(
                        "https://unifi/proxy/network/api/s/default/rest/portforward/existing_id",
                    )
                    .unwrap(),
                ),
                predicate::eq(Some(json!({
                    "_id": "existing_id",
                    "name": "updated-rule",
                    "enabled": true,
                    "pfwd_interface": "wan",
                    "fwd": "192.168.1.101",
                    "destination_ip": "any",
                    "src": "any",
                    "log": false,
                    "dst_port": "80",
                    "fwd_port": "80",
                    "proto": "tcp",
                    "site_id": "default"
                }))),
            )
            .returning(|_, _| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({
                        "meta": { "rc": "ok" },
                        "data": [{
                            "_id": "existing_id",
                            "name": "updated-rule",
                            "enabled": true,
                            "pfwd_interface": "wan",
                            "fwd": "192.168.1.101",
                            "destination_ip": "any",
                            "src": "any",
                            "log": false,
                            "dst_port": "80",
                            "fwd_port": "80",
                            "proto": "tcp",
                            "site_id": "default"
                        }]
                    }),
                ))
            });

        let unifi_client = UnifiClient {
            client: Box::new(mock_http_client),
            base_url: "unifi".to_string(),
            site_name: "default".to_string(),
            dry_run: false,
        };

        let updated_rule = PortForwardRule {
            id: Some("existing_id".to_string()),
            name: "updated-rule".to_string(),
            enabled: true,
            pfwd_interface: "wan".to_string(),
            fwd: "192.168.1.101".to_string(),
            destination_ip: Some("any".to_string()),
            src: "any".to_string(),
            log: false,
            dst_port: serde_json::Value::String("80".to_string()),
            fwd_port: serde_json::Value::String("80".to_string()),
            proto: "tcp".to_string(),
            site_id: "default".to_string(),
        };

        let result_rule = updated_rule.update(&unifi_client).await?;
        assert_eq!(result_rule.name, "updated-rule");
        assert_eq!(result_rule.fwd, "192.168.1.101");

        Ok(())
    }

    #[tokio::test]
    async fn test_port_forward_rule_delete() -> Result<()> {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client
            .expect_delete()
            .once()
            .with(predicate::eq(
                Url::parse(
                    "https://unifi/proxy/network/api/s/default/rest/portforward/existing_id",
                )
                .unwrap(),
            ))
            .returning(|_url| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!(
                        {
                            "meta": { "rc": "ok" },
                            "data": []
                        }
                    ),
                ))
            });

        let unifi_client = UnifiClient {
            client: Box::new(mock_http_client),
            base_url: "unifi".to_string(),
            site_name: "default".to_string(),
            dry_run: false,
        };

        let rule_to_delete = PortForwardRule {
            id: Some("existing_id".to_string()),
            name: "test-rule".to_string(),
            enabled: true,
            pfwd_interface: "wan".to_string(),
            fwd: "192.168.1.100".to_string(),
            destination_ip: Some("any".to_string()),
            src: "any".to_string(),
            log: false,
            dst_port: serde_json::Value::String("80".to_string()),
            fwd_port: serde_json::Value::String("80".to_string()),
            proto: "tcp".to_string(),
            site_id: "default".to_string(),
        };

        rule_to_delete.delete(&unifi_client).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_firewall_group_create() -> Result<()> {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client
            .expect_post()
            .once()
            .with(
                predicate::eq(
                    Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup")
                        .unwrap(),
                ),
                predicate::eq(Some(json!({
                    "name": "test-group",
                    "description": null,
                    "group_type": "address-group",
                    "group_members": ["192.168.1.1"],
                    "site_id": "default"
                }))),
            )
            .returning(|_, _| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({
                        "meta": { "rc": "ok" },
                        "data": [{
                            "_id": "new_group_id",
                            "name": "test-group",
                            "description": null,
                            "group_type": "address-group",
                            "group_members": ["192.168.1.1"],
                            "site_id": "default"
                        }]
                    }),
                ))
            });

        let unifi_client = UnifiClient {
            client: Box::new(mock_http_client),
            base_url: "unifi".to_string(),
            site_name: "default".to_string(),
            dry_run: false,
        };

        let new_group = FirewallGroup {
            id: None,
            name: "test-group".to_string(),
            description: None,
            group_type: "address-group".to_string(),
            group_members: vec!["192.168.1.1".to_string()],
            site_id: "default".to_string(),
        };

        let created_group = new_group.create(&unifi_client).await?;
        assert_eq!(created_group.id, Some("new_group_id".to_string()));
        assert_eq!(created_group.name, "test-group");

        Ok(())
    }

    #[tokio::test]
    async fn test_firewall_group_update() -> Result<()> {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client.expect_put()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup/existing_group_id").unwrap()),
                predicate::eq(Some(json!({
                    "_id": "existing_group_id",
                    "name": "updated-group",
                    "description": null,
                    "group_type": "address-group",
                    "group_members": ["192.168.1.2"],
                    "site_id": "default"
                }))),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({
                "meta": { "rc": "ok" },
                "data": [{
                    "_id": "existing_group_id",
                    "name": "updated-group",
                    "description": null,
                    "group_type": "address-group",
                    "group_members": ["192.168.1.2"],
                    "site_id": "default"
                }]
            }))));

        let unifi_client = UnifiClient {
            client: Box::new(mock_http_client),
            base_url: "unifi".to_string(),
            site_name: "default".to_string(),
            dry_run: false,
        };

        let updated_group = FirewallGroup {
            id: Some("existing_group_id".to_string()),
            name: "updated-group".to_string(),
            description: None,
            group_type: "address-group".to_string(),
            group_members: vec!["192.168.1.2".to_string()],
            site_id: "default".to_string(),
        };

        let result_group = updated_group.update(&unifi_client).await?;
        assert_eq!(result_group.name, "updated-group");
        assert_eq!(result_group.group_members, vec!["192.168.1.2".to_string()]);

        Ok(())
    }

    #[tokio::test]
    async fn test_firewall_group_delete() -> Result<()> {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client.expect_delete()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup/existing_group_id").unwrap()),
            )
            .returning(|_url| Ok(mock_response(reqwest::StatusCode::OK, json!({
                "meta": { "rc": "ok" },
                "data": []
            }))));

        let unifi_client = UnifiClient {
            client: Box::new(mock_http_client),
            base_url: "unifi".to_string(),
            site_name: "default".to_string(),
            dry_run: false,
        };

        let group_to_delete = FirewallGroup {
            id: Some("existing_group_id".to_string()),
            name: "test-group".to_string(),
            description: None,
            group_type: "address-group".to_string(),
            group_members: vec!["192.168.1.1".to_string()],
            site_id: "default".to_string(),
        };

        group_to_delete.delete(&unifi_client).await?;

        Ok(())
    }
}
