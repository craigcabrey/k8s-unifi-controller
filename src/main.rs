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
use tokio;
use tokio::net;
use tokio::signal::unix::{SignalKind, signal};

mod unifi;

/// Resolves an external hostname to a list of IP addresses.
async fn resolve_external_name(external_name: &str) -> Result<Vec<String>> {
    let mut ips = Vec::new();
    for addr in net::lookup_host(format!("{}:0", external_name)).await? {
        ips.push(addr.ip().to_string());
    }
    Ok(ips)
}

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

pub struct Service(k8s_openapi::api::core::v1::Service);

impl Service {
    pub fn get_service_identifier(&self) -> Option<String> {
        let namespace = self.0.metadata.namespace.as_ref()?;
        let name = self.0.metadata.name.as_ref()?;
        Some(format!("{}/{}", namespace, name))
    }

    pub async fn get_external_ips(&self) -> Result<Vec<String>> {
        let service = &self.0;
        let service_ips = match &service.spec {
            Some(spec) => match &spec.external_name {
                Some(external_name) => resolve_external_name(&external_name).await?,
                None => service
                    .status
                    .as_ref()
                    .and_then(|s| s.load_balancer.as_ref())
                    .and_then(|lb| lb.ingress.as_ref())
                    .map_or_else(Vec::new, |ingresses| {
                        ingresses
                            .iter()
                            .filter_map(|ingress| ingress.ip.clone())
                            .collect()
                    }),
            },
            None => Vec::new(),
        };
        Ok(service_ips)
    }

    pub fn get_service_ports(&self) -> Vec<String> {
        self.0
            .spec
            .as_ref()
            .and_then(|spec| spec.ports.as_ref())
            .map_or_else(Vec::new, |ports| {
                ports.iter().map(|p| p.port.to_string()).collect()
            })
    }
}

/// Resolves an external hostname to a list of IP addresses.

async fn upsert_firewall_group(
    group_name: &str,
    service_identifier_base: &str,
    group_type: &str,
    service_ips: Vec<String>,
    unifi_client: &unifi::UnifiClient,
    unifi_firewall_groups: &mut Vec<unifi::FirewallGroup>,
    matched_unifi_group_ids: &mut HashSet<String>,
) -> Result<()> {
    let mut matched_group_index: Option<usize> = None;
    for (i, group) in unifi_firewall_groups.iter().enumerate() {
        if group.name == group_name {
            matched_group_index = Some(i);
            break;
        }
    }

    if let Some(index) = matched_group_index {
        let group = &mut unifi_firewall_groups[index];
        if let Some(group_id) = &group.id {
            matched_unifi_group_ids.insert(group_id.clone());
        }

        // Check if group members need updating
        let current_members: HashSet<&String> = group.group_members.iter().collect();
        let new_members: HashSet<&String> = service_ips.iter().collect();

        if current_members != new_members || group.group_type != group_type {
            info!(
                "Updating firewall group '{}' for service '{}'",
                group.name, service_identifier_base
            );
            let updated_group = unifi::FirewallGroup {
                id: group.id.clone(),
                name: group.name.clone(),
                description: group.description.clone(),
                group_type: group_type.to_string(),
                group_members: service_ips.clone(),
                site_id: unifi_client.site_name.clone(),
            };

            match updated_group.update(unifi_client).await {
                Ok(g) => {
                    info!("Successfully updated firewall group: {}", g.name);
                    *group = g;
                }
                Err(e) => error!("Failed to update firewall group '{}': {}", group.name, e),
            }
        } else {
            info!("Firewall group '{}' is already up to date.", group.name);
        }
    } else {
        // Group not found, need to create
        info!("Firewall group '{}' not found, creating.", group_name);
        let new_group = unifi::FirewallGroup {
            id: None,
            name: group_name.to_string(),
            description: Some(format!(
                "Kubernetes managed firewall group for service {}",
                service_identifier_base
            )),
            group_type: group_type.to_string(),
            group_members: service_ips.clone(),
            site_id: unifi_client.site_name.clone(),
        };

        match new_group.create(unifi_client).await {
            Ok(g) => {
                info!("Successfully created firewall group: {}", g.name);
                unifi_firewall_groups.push(g);
            }
            Err(e) => error!(
                "Failed to create firewall group '{}': {}",
                new_group.name, e
            ),
        }
    }
    Ok(())
}

async fn process_firewall_group(
    service: &Service,
    firewall_group_label: &str,
    unifi_client: &unifi::UnifiClient,
    unifi_firewall_groups: &mut Vec<unifi::FirewallGroup>,
    matched_unifi_group_ids: &mut HashSet<String>,
) -> Result<()> {
    debug!(
        "Processing service for firewall group: {:?}",
        service.0.metadata.name
    );
    let service_identifier_base = if let Some(id) = service.get_service_identifier() {
        id
    } else {
        debug!(
            "Skipping service {:?} due to missing namespace or name",
            service.0.metadata.name
        );
        return Ok(());
    };

    if let Some(labels) = service.0.metadata.labels.as_ref() {
        if labels
            .iter()
            .any(|(key, _)| key.contains(firewall_group_label))
        {
            info!(
                "Processing service for firewall group: {:?}",
                service.0.metadata.name
            );

            let service_ips = service.get_external_ips().await?;

            if service_ips.is_empty() {
                debug!(
                    "No external IPs found for service {:?}, skipping firewall group processing.",
                    service.0.metadata.name
                );
                return Ok(());
            }

            debug!(
                "Service IPs for service {:?}: {:?}",
                service.0.metadata.name, service_ips
            );

            let (ipv4_ips, ipv6_ips): (Vec<String>, Vec<String>) = service_ips
                .into_iter()
                .partition(|ip_str| ip_str.parse::<IpAddr>().map_or(false, |ip| ip.is_ipv4()));

            let mut processed_group_names = HashSet::new();

            // Process IPv4 group
            if !ipv4_ips.is_empty() {
                let ipv4_group_name = format!("{}-ipv4", service_identifier_base);
                upsert_firewall_group(
                    &ipv4_group_name,
                    &service_identifier_base,
                    "address-group",
                    ipv4_ips,
                    unifi_client,
                    unifi_firewall_groups,
                    matched_unifi_group_ids,
                )
                .await?;
                processed_group_names.insert(ipv4_group_name);
            }

            // Process IPv6 group
            if !ipv6_ips.is_empty() {
                let ipv6_group_name = format!("{}-ipv6", service_identifier_base);
                upsert_firewall_group(
                    &ipv6_group_name,
                    &service_identifier_base,
                    "ipv6-address-group",
                    ipv6_ips,
                    unifi_client,
                    unifi_firewall_groups,
                    matched_unifi_group_ids,
                )
                .await?;
                processed_group_names.insert(ipv6_group_name);
            }

            // Process Port Group
            let service_ports: Vec<String> = service.get_service_ports();

            if !service_ports.is_empty() {
                let port_group_name = format!("{}-ports", service_identifier_base);
                upsert_firewall_group(
                    &port_group_name,
                    &service_identifier_base,
                    "port-group",
                    service_ports,
                    unifi_client,
                    unifi_firewall_groups,
                    matched_unifi_group_ids,
                )
                .await?;
                processed_group_names.insert(port_group_name);
            }

            // Delete any old groups that are no longer needed (e.g., if a service switched from IPv4+IPv6 to only IPv4)
            for group in unifi_firewall_groups {
                if group.name.starts_with(&service_identifier_base)
                    && !processed_group_names.contains(&group.name)
                {
                    if let Some(_group_id) = &group.id {
                        info!("Deleting stale firewall group: '{}'", group.name);
                        match group.delete(unifi_client).await {
                            Ok(_) => {
                                info!("Successfully deleted stale firewall group: {}", group.name)
                            }
                            Err(e) => error!(
                                "Failed to delete stale firewall group '{}': {}",
                                group.name, e
                            ),
                        }
                    }
                }
            }
        }
    } else {
        debug!("Service {:?} has no labels", service.0.metadata.name);
    }
    Ok(())
}

async fn process_port_forwards(
    service: &Service,
    label: &str,
    unifi_client: &unifi::UnifiClient,
    unifi_port_forward_rules: &mut Vec<unifi::PortForwardRule>,
    matched_unifi_rule_ids: &mut HashSet<String>,
    unifi_interface: &str,
) -> Result<()> {
    debug!("Processing service: {:?}", service.0.metadata.name);
    let service_identifier_base = if let Some(id) = service.get_service_identifier() {
        id
    } else {
        debug!(
            "Skipping service {:?} due to missing namespace or name",
            service.0.metadata.name
        );
        return Ok(());
    };

    let service_ips = service.get_external_ips().await?;

    let external_ip = service_ips
        .iter()
        .find(|ip_str| ip_str.parse::<IpAddr>().map_or(false, |ip| ip.is_ipv4()));

    if let Some(labels) = service.0.metadata.labels.as_ref() {
        if labels.iter().any(|(key, _)| key.contains(label)) {
            info!("Processing service: {:?}", service.0.metadata.name);

            let service_ports = service
                .0
                .spec
                .as_ref()
                .and_then(|spec| spec.ports.as_ref())
                .map_or_else(Vec::new, |ports| ports.clone());

            for s_port in service_ports {
                let protocol = s_port
                    .protocol
                    .as_ref()
                    .map_or("tcp".to_string(), |p| p.to_string().to_lowercase());
                let full_identifier =
                    format!("{}/{}/{}", service_identifier_base, protocol, s_port.port);

                let mut matched_rule_index: Option<usize> = None;
                for (i, rule) in unifi_port_forward_rules.iter().enumerate() {
                    if rule.name == full_identifier {
                        matched_rule_index = Some(i);
                        break;
                    }
                }

                if let Some(index) = matched_rule_index {
                    let rule = &mut unifi_port_forward_rules[index];
                    if let Some(rule_id) = &rule.id {
                        matched_unifi_rule_ids.insert(rule_id.clone());
                    }

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

                    if let Some(ext_ip) = external_ip {
                        let current_fwd_ip = &rule.fwd;
                        let current_fwd_port = match &rule.fwd_port {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            _ => "".to_string(),
                        };

                        if current_fwd_ip != ext_ip || current_fwd_port != s_port.port.to_string() {
                            info!(
                                "Updating port forward rule '{}' for service '{}'",
                                rule.name, full_identifier
                            );
                            let updated_rule = unifi::PortForwardRule {
                                id: rule.id.clone(),
                                name: rule.name.clone(),
                                enabled: rule.enabled,
                                pfwd_interface: rule.pfwd_interface.clone(),
                                fwd: ext_ip.clone(),
                                destination_ip: rule.destination_ip.clone(),
                                src: rule.src.clone(),
                                log: rule.log,
                                dst_port: serde_json::Value::String(s_port.port.to_string()),
                                fwd_port: serde_json::Value::String(s_port.port.to_string()),
                                proto: rule.proto.clone(),
                                site_id: rule.site_id.clone(),
                            };

                            match updated_rule.update(unifi_client).await {
                                Ok(r) => {
                                    info!("Successfully updated port forward rule: {}", r.name);
                                    *rule = r;
                                }
                                Err(e) => error!(
                                    "Failed to update port forward rule '{}': {}",
                                    rule.name, e
                                ),
                            }
                        } else {
                            info!("Port forward rule '{}' is already up to date.", rule.name);
                        }
                    } else {
                        debug!(
                            "Could not get external IP for service '{}'.",
                            full_identifier
                        );
                    }
                } else {
                    // Rule not found, need to create
                    info!(
                        "Port forward rule '{}' not found, creating.",
                        full_identifier
                    );
                    if let Some(ext_ip) = external_ip {
                        let new_rule = unifi::PortForwardRule {
                            id: None,
                            name: full_identifier.clone(),
                            enabled: true,
                            pfwd_interface: unifi_interface.to_string(),
                            fwd: ext_ip.clone(),
                            destination_ip: Some("any".to_string()),
                            src: "any".to_string(),
                            log: false,
                            dst_port: serde_json::Value::String(s_port.port.to_string()),
                            fwd_port: serde_json::Value::String(s_port.port.to_string()),
                            proto: protocol.clone(),
                            site_id: unifi_client.site_name.clone(),
                        };

                        match new_rule.create(unifi_client).await {
                            Ok(r) => {
                                info!("Successfully created port forward rule: {}", r.name);
                                unifi_port_forward_rules.push(r);
                            }
                            Err(e) => error!(
                                "Failed to create port forward rule '{}': {}",
                                new_rule.name, e
                            ),
                        }
                    } else {
                        debug!(
                            "Cannot create port forward rule '{}': external IP not found for service.",
                            full_identifier
                        );
                    }
                }
            }
        }
    } else {
        debug!("Service {:?} has no labels", service.0.metadata.name);
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
    )
    .await?;

    info!("Unifi client configured");

    let mut port_forward_rules = unifi::PortForwardRule::list(&unifi_client).await?;
    debug!("Port forward rules: {:?}", port_forward_rules);
    let mut firewall_groups = unifi::FirewallGroup::list(&unifi_client).await?;
    debug!("Firewall groups: {:?}", firewall_groups);

    let services: Api<k8s_openapi::api::core::v1::Service> = Api::all(client);

    let mut matched_unifi_rule_ids: HashSet<String> = HashSet::new();
    let mut matched_unifi_group_ids: HashSet<String> = HashSet::new();

    info!("Processing all services once");
    let lp = ListParams::default();
    for service in services.list(&lp).await? {
        let k8s_service = Service(service);
        process_port_forwards(
            &k8s_service,
            &cli.label,
            &unifi_client,
            &mut port_forward_rules,
            &mut matched_unifi_rule_ids,
            &cli.unifi_interface,
        )
        .await?;
        process_firewall_group(
            &k8s_service,
            &cli.firewall_group_label,
            &unifi_client,
            &mut firewall_groups,
            &mut matched_unifi_group_ids,
        )
        .await?;
    }
    if cli.watch {
        info!("Watching for service events");
        let wc = watcher::Config::default();
        let mut stream = watcher(services, wc).boxed();
        let mut sigint = signal(SignalKind::interrupt())?;

        loop {
            tokio::select! {
                service = stream.try_next() => {
                    match service {
                        Ok(Some(event)) => {
                            match event {
                                watcher::Event::Apply(s) => {
                                    let k8s_service = Service(s);
                                    if let Err(e) = process_port_forwards(&k8s_service, &cli.label, &unifi_client, &mut port_forward_rules, &mut matched_unifi_rule_ids, &cli.unifi_interface).await {
                                        error!("Failed to process service: {}", e);
                                    }
                                    if let Err(e) = process_firewall_group(&k8s_service, &cli.firewall_group_label, &unifi_client, &mut firewall_groups, &mut matched_unifi_group_ids).await {
                                        error!("Failed to process firewall group for service: {}", e);
                                    }
                                },
                                watcher::Event::Delete(s) => {
                                    let k8s_service = Service(s);
                                    info!("Service {:?} deleted, cleaning up Unifi resources", k8s_service.0.metadata.name);
                                    if let Some(service_identifier_base) = k8s_service.get_service_identifier() {
                                        // Clean up port forward rules
                                        for rule in &port_forward_rules {
                                            if rule.name.starts_with(&format!("{}/", service_identifier_base)) {
                                                info!("Deleting port forward rule '{}' for deleted service '{}'", rule.name, service_identifier_base);
                                                    match rule.delete(&unifi_client).await {
                                                        Ok(_) => info!("Successfully deleted port forward rule: {}", rule.name),
                                                        Err(e) => error!("Failed to delete port forward rule '{}': {}", rule.name, e),
                                                    }
                                            }
                                        }

                                        // Clean up firewall groups
                                        for group in &firewall_groups {
                                            if group.name.starts_with(&service_identifier_base) {
                                                info!("Deleting firewall group '{}' for deleted service '{}'", group.name, service_identifier_base);
                                                    match group.delete(&unifi_client).await {
                                                        Ok(_) => info!("Successfully deleted firewall group: {}", group.name),
                                                        Err(e) => error!("Failed to delete firewall group '{}': {}", group.name, e),
                                                    }
                                            }
                                        }
                                    }
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
            }
        }
    }

    // Delete unmatched Unifi port forward rules
    let mut rules_to_delete = Vec::new();
    for rule in &port_forward_rules {
        match &rule.id {
            Some(rule_id) => {
                if !matched_unifi_rule_ids.contains(rule_id) {
                    rules_to_delete.push(rule.clone());
                }
            }
            None => (),
        }
    }

    for rule in rules_to_delete {
        info!("Deleting unmatched port forward rule: '{}'", rule.name);
        match rule.delete(&unifi_client).await {
            Ok(_) => info!("Successfully deleted port forward rule: {}", rule.name),
            Err(e) => error!("Failed to delete port forward rule '{}': {}", rule.name, e),
        }
    }

    port_forward_rules
        .retain(|rule| matched_unifi_rule_ids.contains(rule.id.as_ref().unwrap_or(&String::new())));

    // Delete unmatched Unifi firewall groups
    let mut groups_to_delete = Vec::new();
    for group in &firewall_groups {
        match &group.id {
            Some(group_id) => {
                if !matched_unifi_group_ids.contains(group_id) {
                    groups_to_delete.push(group.clone());
                }
            }
            None => (),
        }
    }

    for group in groups_to_delete {
        info!("Deleting unmatched firewall group: '{}'", group.name);
        match group.delete(&unifi_client).await {
            Ok(_) => info!("Successfully deleted firewall group: {}", group.name),
            Err(e) => error!("Failed to delete firewall group '{}': {}", group.name, e),
        }
    }

    firewall_groups.retain(|group| {
        matched_unifi_group_ids.contains(group.id.as_ref().unwrap_or(&String::new()))
    });

    Ok(())
}
