use clap::Parser;
use futures::{StreamExt, TryStreamExt};
use kube::{
    Client, Config,
    api::{Api, ListParams},
    runtime::watcher,
};

use anyhow::Result;
use log::{LevelFilter, debug, error, info};
use std::collections::HashSet;
use std::net::IpAddr;

use tokio::signal::unix::{SignalKind, signal};

mod models;
mod unifi;
use crate::models::Service;

/// A Kubernetes controller to manage Unifi port forwards
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    debug: bool,

    /// Do not make any mutable changes (best effort)
    #[arg(long)]
    dry_run: bool,

    /// Label on services to track for port forwards
    #[arg(long, default_value = "io.github.craigcabrey/unifi-forward-ports")]
    label: String,

    /// Label on services to track for firewall groups
    #[arg(long, default_value = "io.github.craigcabrey/unifi-firewall-group")]
    firewall_group_label: String,

    /// Continue to watch for service events (act as an "controller")
    #[arg(long)]
    watch: bool,

    /// Time to wait for events while watching Kubernetes event stream
    #[arg(long)]
    watch_timeout: Option<u64>,

    /// Use the config typically located in ~/.kube for cluster access
    #[arg(long)]
    local_cluster: bool,

    /// Interface from which to setup port forwards
    #[arg(long, default_value = "wan")]
    unifi_interface: String,

    /// Hostname of the Unifi Dream Machine
    #[arg(long, default_value = "unifi")]
    unifi_hostname: String,

    /// Sitename in the Unifi Network application
    #[arg(long, default_value = "default")]
    unifi_sitename: String,

    /// Do not validate server certificate (Unifi equipment comes loaded with self-signed certificates)
    #[arg(long)]
    unifi_insecure: bool,

    /// Token for API access (also settable via UNIFI_OPERATOR_UNIFI_TOKEN environment variable)
    #[arg(long, env = "UNIFI_OPERATOR_UNIFI_TOKEN")]
    unifi_token: String,
}

/// Resolves an external hostname to a list of IP addresses.

async fn process_firewall_group(
    service: &Service,
    label: &str,
    unifi_client: &unifi::UnifiClient,
) -> Result<()> {
    debug!("Checking service for firewall group: {:?}", service);

    match service.labels() {
        Some(labels) => {
            if !labels.contains_key(label) {
                debug!(
                    "Skipping service {:?} without firewall group label",
                    service
                );
                return Ok(());
            }
        }
        None => {
            debug!("Skipping service {:?} without labels", service);
            return Ok(());
        }
    }

    info!("Processing service for firewall group: {:?}", service);

    let desired_groups = service.firewall_groups().await?;
    let mut unifi_firewall_groups = unifi::FirewallGroup::list(unifi_client).await?;

    for mut desired_group in desired_groups {
        desired_group.site_id = unifi_client.site_name.clone();
        match unifi_firewall_groups
            .iter()
            .find(|g| g.name == desired_group.name)
            .cloned()
        {
            Some(mut existing_group) => {
                let current_members: HashSet<&String> =
                    existing_group.group_members.iter().collect();
                let new_members: HashSet<&String> = desired_group.group_members.iter().collect();

                if current_members != new_members
                    || existing_group.group_type != desired_group.group_type
                {
                    info!(
                        "Updating firewall group '{}' for service '{:?}'",
                        existing_group.name, service
                    );
                    existing_group.group_type = desired_group.group_type.clone();
                    existing_group.group_members = desired_group.group_members.clone();

                    match existing_group.update(unifi_client).await {
                        Ok(g) => {
                            info!("Successfully updated firewall group: {}", g.name);
                        }
                        Err(e) => error!(
                            "Failed to update firewall group '{}': {}",
                            existing_group.name, e
                        ),
                    }
                } else {
                    info!(
                        "Firewall group '{}' is already up to date.",
                        existing_group.name
                    );
                }
            }
            None => {
                info!(
                    "Firewall group '{}' not found, creating.",
                    desired_group.name
                );
                match desired_group.create(unifi_client).await {
                    Ok(g) => {
                        info!("Successfully created firewall group: {}", g.name);
                        unifi_firewall_groups.push(g);
                    }
                    Err(e) => error!(
                        "Failed to create firewall group '{}': {}",
                        desired_group.name, e
                    ),
                }
            }
        }
    }

    Ok(())
}

async fn process_port_forwards(
    service: &Service,
    label: &str,
    unifi_client: &unifi::UnifiClient,
    unifi_interface: &str,
) -> Result<()> {
    debug!("Checking service for port forwards: {:?}", service);

    match service.labels() {
        Some(labels) => {
            if !labels.contains_key(label) {
                debug!("Skipping service {:?} without port forward label", service);
                return Ok(());
            }
        }
        None => {
            debug!("Skipping service {:?} without labels", service);
            return Ok(());
        }
    }

    let desired_rules = service.port_forward_rules(unifi_interface).await?;
    let unifi_port_forward_rules = unifi::PortForwardRule::list(unifi_client).await?;

    for mut desired_rule in desired_rules {
        desired_rule.site_id = unifi_client.site_name.clone();
        match unifi_port_forward_rules
            .iter()
            .find(|rule| rule.name == desired_rule.name)
            .cloned()
        {
            Some(mut rule) => {
                let fwd_ip: IpAddr = match rule.fwd.parse() {
                    Ok(ip) => ip,
                    Err(_) => {
                        error!("Failed to parse fwd IP address: {}", rule.fwd);
                        continue;
                    }
                };

                if fwd_ip.is_ipv6() {
                    debug!("Skipping IPv6 port forward rule: {:?}", rule);
                    continue;
                }

                let current_fwd_ip = &rule.fwd;
                let current_fwd_port = match &rule.fwd_port {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => "".to_string(),
                };

                if current_fwd_ip != &desired_rule.fwd
                    || current_fwd_port != desired_rule.fwd_port.as_str().unwrap_or_default()
                {
                    info!(
                        "Updating port forward rule '{}' for service '{:?}'",
                        rule.name, service
                    );
                    rule.fwd = desired_rule.fwd.clone();
                    rule.fwd_port = desired_rule.fwd_port.clone();

                    match rule.update(unifi_client).await {
                        Ok(r) => {
                            info!("Successfully updated port forward rule: {}", r.name);
                        }
                        Err(e) => {
                            error!("Failed to update port forward rule '{}': {}", rule.name, e)
                        }
                    }
                } else {
                    info!("Port forward rule '{}' is already up to date.", rule.name);
                }
            }
            None => {
                info!(
                    "Port forward rule '{}' not found, creating.",
                    desired_rule.name
                );
                match desired_rule.create(unifi_client).await {
                    Ok(r) => {
                        info!("Successfully created port forward rule: {}", r.name);
                    }
                    Err(e) => error!(
                        "Failed to create port forward rule '{}': {}",
                        desired_rule.name, e
                    ),
                }
            }
        }
    }

    Ok(())
}

async fn cleanup_unmatched_resources(
    unifi_client: &unifi::UnifiClient,
    services: &[Service],
    label: &str,
    firewall_group_label: &str,
    unifi_interface: &str,
) -> Result<()> {
    let mut desired_rules = HashSet::new();
    let mut desired_groups = HashSet::new();

    for service in services {
        if let Some(labels) = service.labels() {
            if labels.iter().any(|(key, _)| key.contains(label)) {
                for rule in service.port_forward_rules(unifi_interface).await? {
                    desired_rules.insert(rule.name);
                }
            }
            if labels
                .iter()
                .any(|(key, _)| key.contains(firewall_group_label))
            {
                for group in service.firewall_groups().await? {
                    desired_groups.insert(group.name);
                }
            }
        }
    }

    let port_forward_rules = unifi::PortForwardRule::list(unifi_client).await?;
    for rule in &port_forward_rules {
        if !desired_rules.contains(&rule.name) {
            info!("Deleting unmatched port forward rule: '{}'", rule.name);
            match rule.delete(unifi_client).await {
                Ok(_) => info!("Successfully deleted port forward rule: {}", rule.name),
                Err(e) => error!("Failed to delete port forward rule '{}': {}", rule.name, e),
            }
        }
    }

    let firewall_groups = unifi::FirewallGroup::list(unifi_client).await?;
    for group in &firewall_groups {
        if !desired_groups.contains(&group.name) {
            info!("Deleting unmatched firewall group: '{}'", group.name);
            match group.delete(unifi_client).await {
                Ok(_) => info!("Successfully deleted firewall group: {}", group.name),
                Err(e) => error!("Failed to delete firewall group '{}': {}", group.name, e),
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut builder = env_logger::Builder::new();

    if cli.debug {
        builder.filter_level(LevelFilter::Debug);
    } else {
        builder.filter_level(LevelFilter::Info);
    }

    builder.init();

    let config = if cli.local_cluster {
        info!("Using local cluster config");
        Config::infer().await?
    } else {
        info!("Using in-cluster config");
        Config::incluster_env()?
    };
    let client = Client::try_from(config)?;

    let unifi_client = unifi::UnifiClient::new(
        cli.unifi_hostname,
        cli.unifi_sitename,
        cli.unifi_token,
        cli.unifi_insecure,
        cli.dry_run,
        None,
    )
    .await?;

    info!("Unifi client configured");

    let services_api: Api<k8s_openapi::api::core::v1::Service> = Api::all(client);
    let services: Vec<Service> = services_api
        .list(&ListParams::default())
        .await?
        .into_iter()
        .map(Service)
        .collect();

    info!("Processing all services once");
    for service in &services {
        if let Err(e) =
            process_port_forwards(&service, &cli.label, &unifi_client, &cli.unifi_interface).await
        {
            error!("Error occurred while processing port forwards: {:?}", e)
        };

        if let Err(e) =
            process_firewall_group(&service, &cli.firewall_group_label, &unifi_client).await
        {
            error!("Error occurred while processing firewall group: {:?}", e)
        };
    }

    if cli.watch {
        info!("Watching for service events");
        let wc = watcher::Config::default();
        let mut stream = watcher(services_api.clone(), wc).boxed();
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        loop {
            tokio::select! {
                service = stream.try_next() => {
                    match service {
                        Ok(Some(event)) => {
                            match event {
                                watcher::Event::Apply(s) => {
                                    let service = Service(s);
                                    if let Err(e) = process_port_forwards(&service, &cli.label, &unifi_client, &cli.unifi_interface).await {
                                        error!("Failed to process service: {}", e);
                                    }
                                    if let Err(e) = process_firewall_group(&service, &cli.firewall_group_label, &unifi_client).await {
                                        error!("Failed to process firewall group for service: {}", e);
                                    }
                                },
                                watcher::Event::Delete(s) => {
                                    let service = Service(s);
                                    info!("Service {:?} deleted, cleaning up Unifi resources", service);
                                    // TODO: This is not ideal, but it's the best we can do for now
                                    let services = services_api
                                        .list(&ListParams::default())
                                        .await?;
                                    let services: Vec<Service> = services.into_iter().map(Service).collect();
                                    let _ = cleanup_unmatched_resources(&unifi_client, &services, &cli.label, &cli.firewall_group_label, &cli.unifi_interface).await;
                                },
                                _ => debug!("Ignoring other watcher events"),
                            }
                        },
                        Ok(None) => info!("Watcher stream ended"),
                        Err(e) => error!("Watcher error: {}", e),
                    }
                },
                _ = sigint.recv() => {
                    info!("Received SIGINT, shutting down");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down");
                    break;
                }
            }
        }
    }

    cleanup_unmatched_resources(
        &unifi_client,
        &services,
        &cli.label,
        &cli.firewall_group_label,
        &cli.unifi_interface,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use crate::unifi::MockHttpClient;
    use http;
    use hyper;
    use k8s_openapi::api::core::v1::{
        LoadBalancerIngress, LoadBalancerStatus, Service as K8sService, ServicePort, ServiceSpec,
        ServiceStatus,
    };
    use kube::api::ObjectMeta;
    use mockall::predicate;
    use reqwest::Url;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::Cursor;
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

    fn create_test_k8s_service(
        name: &str,
        namespace: &str,
        labels: Option<BTreeMap<String, String>>,
        external_name: Option<String>,
        ips: Vec<String>,
        ports: Vec<i32>,
    ) -> K8sService {
        let mut metadata = ObjectMeta::default();
        metadata.name = Some(name.to_string());
        metadata.namespace = Some(namespace.to_string());
        metadata.labels = labels;

        let mut spec = ServiceSpec::default();
        spec.external_name = external_name;
        spec.ports = Some(
            ports
                .into_iter()
                .map(|p| ServicePort {
                    port: p,
                    ..Default::default()
                })
                .collect(),
        );

        let mut status = ServiceStatus::default();
        if !ips.is_empty() {
            status.load_balancer = Some(LoadBalancerStatus {
                ingress: Some(
                    ips.into_iter()
                        .map(|ip| LoadBalancerIngress {
                            ip: Some(ip),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            });
        }

        K8sService {
            metadata,
            spec: Some(spec),
            status: Some(status),
            ..Default::default()
        }
    }

    // Mock UnifiClient for testing
    async fn mock_unifi_client(mock_http_client: MockHttpClient) -> unifi::UnifiClient {
        unifi::UnifiClient::new(
            "unifi".to_string(),
            "default".to_string(),
            "test_token".to_string(),
            false,
            false,
            Some(Box::new(mock_http_client)),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_process_port_forwards_no_label() -> Result<()> {
        let k8s_service =
            create_test_k8s_service("test-service", "default", None, None, vec![], vec![]);
        let service = Service(k8s_service);
        let mock_http_client = MockHttpClient::new(); // No expectations, as it shouldn't be called
        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result =
            process_port_forwards(&service, "some-other-label", &unifi_client, "wan").await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_process_port_forwards_new_rule() -> Result<()> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "io.github.craigcabrey/unifi-forward-ports".to_string(),
            "true".to_string(),
        );
        let k8s_service = create_test_k8s_service(
            "test-service",
            "default",
            Some(labels),
            None,
            vec!["192.168.1.1".to_string()],
            vec![80],
        );
        let service = Service(k8s_service);

        let mut mock_http_client = MockHttpClient::new();
        // Expect list to be called and return empty
        mock_http_client
            .expect_get()
            .once()
            .with(predicate::eq(
                Url::parse("https://unifi/proxy/network/api/s/default/rest/portforward").unwrap(),
            ))
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({"meta": {"rc": "ok"}, "data": []}),
                ))
            });

        // Expect create to be called
        mock_http_client.expect_post()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/portforward").unwrap()),
                predicate::function(|body: &Option<serde_json::Value>| {
                    if let Some(json_body) = body {
                        json_body["name"] == "default/test-service/tcp/80"
                    } else { false }
                }),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [{"_id": "new_id", "name": "default/test-service/tcp/80"}]} ))));

        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result = process_port_forwards(
            &service,
            "io.github.craigcabrey/unifi-forward-ports",
            &unifi_client,
            "wan",
        )
        .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_process_port_forwards_update_rule() -> Result<()> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "io.github.craigcabrey/unifi-forward-ports".to_string(),
            "true".to_string(),
        );
        let k8s_service = create_test_k8s_service(
            "test-service",
            "default",
            Some(labels),
            None,
            vec!["192.168.1.2".to_string()],
            vec![80],
        );
        let service = Service(k8s_service);

        let mut mock_http_client = MockHttpClient::new();
        // Expect list to be called and return an existing rule that needs update
        mock_http_client
            .expect_get()
            .once()
            .with(predicate::eq(
                Url::parse("https://unifi/proxy/network/api/s/default/rest/portforward").unwrap(),
            ))
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({"meta": {"rc": "ok"}, "data": [{
                    "_id": "existing_id",
                    "name": "default/test-service/tcp/80",
                    "enabled": true,
                    "pfwd_interface": "wan",
                    "fwd": "192.168.1.1", // Old IP
                    "destination_ip": "any",
                    "src": "any",
                    "log": false,
                    "dst_port": "80",
                    "fwd_port": "80",
                    "proto": "tcp",
                    "site_id": "default"
                }]} ),
                ))
            });

        // Expect update to be called
        mock_http_client.expect_put()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/portforward/existing_id").unwrap()),
                predicate::function(|body: &Option<serde_json::Value>| {
                    if let Some(json_body) = body {
                        json_body["fwd"] == "192.168.1.2" // New IP
                    } else { false }
                }),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [{"_id": "existing_id", "name": "default/test-service/tcp/80", "fwd": "192.168.1.2"}]} ))));

        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result = process_port_forwards(
            &service,
            "io.github.craigcabrey/unifi-forward-ports",
            &unifi_client,
            "wan",
        )
        .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_process_firewall_group_no_label() -> Result<()> {
        let k8s_service =
            create_test_k8s_service("test-service", "default", None, None, vec![], vec![]);
        let service = Service(k8s_service);
        let mock_http_client = MockHttpClient::new(); // No expectations
        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result = process_firewall_group(&service, "some-other-label", &unifi_client).await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_process_firewall_group_new_group() -> Result<()> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "io.github.craigcabrey/unifi-firewall-group".to_string(),
            "true".to_string(),
        );
        let k8s_service = create_test_k8s_service(
            "test-service",
            "default",
            Some(labels),
            None,
            vec!["192.168.1.1".to_string()],
            vec![80],
        );
        let service = Service(k8s_service);

        let mut mock_http_client = MockHttpClient::new();
        // Expect list to be called and return empty
        mock_http_client
            .expect_get()
            .once()
            .with(predicate::eq(
                Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup").unwrap(),
            ))
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({"meta": {"rc": "ok"}, "data": []}),
                ))
            });

        // Expect create to be called for ipv4 group
        mock_http_client.expect_post()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup").unwrap()),
                predicate::function(|body: &Option<serde_json::Value>| {
                    if let Some(json_body) = body {
                        json_body["name"] == "default/test-service-ipv4"
                    } else { false }
                }),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [{"_id": "new_ipv4_id", "name": "default/test-service-ipv4"}]} ))));

        // Expect create to be called for ports group
        mock_http_client.expect_post()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup").unwrap()),
                predicate::function(|body: &Option<serde_json::Value>| {
                    if let Some(json_body) = body {
                        json_body["name"] == "default/test-service-ports"
                    } else { false }
                }),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [{"_id": "new_ports_id", "name": "default/test-service-ports"}]} ))));

        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result = process_firewall_group(
            &service,
            "io.github.craigcabrey/unifi-firewall-group",
            &unifi_client,
        )
        .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_process_firewall_group_update_group() -> Result<()> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "io.github.craigcabrey/unifi-firewall-group".to_string(),
            "true".to_string(),
        );
        let k8s_service = create_test_k8s_service(
            "test-service",
            "default",
            Some(labels),
            None,
            vec!["192.168.1.2".to_string()],
            vec![81],
        );
        let service = Service(k8s_service);

        let mut mock_http_client = MockHttpClient::new();
        // Expect list to be called and return existing groups that need update
        let ipv4_group_json = json!({
            "_id": "existing_ipv4_id",
            "name": "default/test-service-ipv4",
            "description": null,
            "group_type": "address-group",
            "group_members": ["192.168.1.1"], // Old IP
            "site_id": "default"
        });

        let ports_group_json = json!({
            "_id": "existing_ports_id",
            "name": "default/test-service-ports",
            "description": null,
            "group_type": "port-group",
            "group_members": ["80"], // Old port
            "site_id": "default"
        });

        mock_http_client.expect_get()
            .once()
            .with(predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup").unwrap()))
            .returning(move |_| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [ipv4_group_json.clone(), ports_group_json.clone()]}))));

        // Expect update to be called for ipv4 group
        mock_http_client.expect_put()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup/existing_ipv4_id").unwrap()),
                predicate::function(|body: &Option<serde_json::Value>| {
                    if let Some(json_body) = body {
                        json_body["group_members"][0] == "192.168.1.2" // New IP
                    } else { false }
                }),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [{"_id": "existing_ipv4_id", "name": "default/test-service-ipv4", "group_members": ["192.168.1.2"]} ]} ))));

        // Expect update to be called for ports group
        mock_http_client.expect_put()
            .once()
            .with(
                predicate::eq(Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup/existing_ports_id").unwrap()),
                predicate::function(|body: &Option<serde_json::Value>| {
                    if let Some(json_body) = body {
                        json_body["group_members"][0] == "81" // New port
                    } else { false }
                }),
            )
            .returning(|_, _| Ok(mock_response(reqwest::StatusCode::OK, json!({"meta": {"rc": "ok"}, "data": [{"_id": "existing_ports_id", "name": "default/test-service-ports", "group_members": ["81"]}]} ))));

        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result = process_firewall_group(
            &service,
            "io.github.craigcabrey/unifi-firewall-group",
            &unifi_client,
        )
        .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_unmatched_resources() -> Result<()> {
        let label = "io.github.craigcabrey/unifi-forward-ports";
        let firewall_group_label = "io.github.craigcabrey/unifi-firewall-group";
        let unifi_interface = "wan";

        // Service 1: Has labels, should match one rule and one group
        let mut labels1 = BTreeMap::new();
        labels1.insert(label.to_string(), "true".to_string());
        labels1.insert(firewall_group_label.to_string(), "true".to_string());
        let k8s_service1 = create_test_k8s_service(
            "test-service-1",
            "default",
            Some(labels1),
            None,
            vec!["192.168.1.10".to_string()],
            vec![8080],
        );
        let service1 = Service(k8s_service1);

        // Service 2: No relevant labels, should not match any rule or group
        let k8s_service2 =
            create_test_k8s_service("test-service-2", "default", None, None, vec![], vec![]);
        let service2 = Service(k8s_service2);

        let services = vec![service1.clone(), service2.clone()];

        let mut mock_http_client = MockHttpClient::new();

        // Mock PortForwardRule::list
        mock_http_client
            .expect_get()
            .with(predicate::eq(
                Url::parse("https://unifi/proxy/network/api/s/default/rest/portforward").unwrap(),
            ))
            .times(1) // Called once by cleanup
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({
                        "meta": {"rc": "ok"},
                        "data": [
                            // Matched rule
                            {
                                "_id": "matched_pf_id",
                                "name": "default/test-service-1/tcp/8080",
                                "enabled": true,
                                "pfwd_interface": "wan",
                                "fwd": "192.168.1.10",
                                "destination_ip": "any",
                                "src": "any",
                                "log": false,
                                "dst_port": "8080",
                                "fwd_port": "8080",
                                "proto": "tcp",
                                "site_id": "default"
                            },
                            // Unmatched rule
                            {
                                "_id": "unmatched_pf_id",
                                "name": "unmatched-pf-rule",
                                "enabled": true,
                                "pfwd_interface": "wan",
                                "fwd": "192.168.1.99",
                                "destination_ip": "any",
                                "src": "any",
                                "log": false,
                                "dst_port": "9999",
                                "fwd_port": "9999",
                                "proto": "tcp",
                                "site_id": "default"
                            }
                        ]
                    }),
                ))
            });

        // Mock FirewallGroup::list
        mock_http_client
            .expect_get()
            .with(predicate::eq(
                Url::parse("https://unifi/proxy/network/api/s/default/rest/firewallgroup").unwrap(),
            ))
            .times(1) // Called once by cleanup
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({
                        "meta": {"rc": "ok"},
                        "data": [
                            // Matched group (ipv4)
                            {
                                "_id": "matched_fg_ipv4_id",
                                "name": "default/test-service-1-ipv4",
                                "description": null,
                                "group_type": "address-group",
                                "group_members": ["192.168.1.10"],
                                "site_id": "default"
                            },
                            // Matched group (ports)
                            {
                                "_id": "matched_fg_ports_id",
                                "name": "default/test-service-1-ports",
                                "description": null,
                                "group_type": "port-group",
                                "group_members": ["8080"],
                                "site_id": "default"
                            },
                            // Unmatched group
                            {
                                "_id": "unmatched_fg_id",
                                "name": "unmatched-fg-group",
                                "description": null,
                                "group_type": "address-group",
                                "group_members": ["192.168.1.99"],
                                "site_id": "default"
                            }
                        ]
                    }),
                ))
            });

        // Expect delete for the unmatched port forward rule
        mock_http_client
            .expect_delete()
            .once()
            .with(predicate::eq(
                Url::parse(
                    "https://unifi/proxy/network/api/s/default/rest/portforward/unmatched_pf_id",
                )
                .unwrap(),
            ))
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({"meta": {"rc": "ok"}, "data": []}),
                ))
            });

        // Expect delete for the unmatched firewall group
        mock_http_client
            .expect_delete()
            .once()
            .with(predicate::eq(
                Url::parse(
                    "https://unifi/proxy/network/api/s/default/rest/firewallgroup/unmatched_fg_id",
                )
                .unwrap(),
            ))
            .returning(|_| {
                Ok(mock_response(
                    reqwest::StatusCode::OK,
                    json!({"meta": {"rc": "ok"}, "data": []}),
                ))
            });

        let unifi_client = mock_unifi_client(mock_http_client).await;

        let result = cleanup_unmatched_resources(
            &unifi_client,
            &services,
            label,
            firewall_group_label,
            unifi_interface,
        )
        .await;

        assert!(result.is_ok());
        Ok(())
    }
}
