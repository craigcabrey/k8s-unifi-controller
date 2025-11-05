use anyhow::Result;

use std::collections::BTreeMap;
use std::net::IpAddr;
use tokio::net;

use crate::unifi;

/// Resolves an external hostname to a list of IP addresses.
async fn resolve_external_name(external_name: &str) -> Result<Vec<String>> {
    let mut ips = Vec::new();
    for addr in net::lookup_host(format!("{}:0", external_name)).await? {
        ips.push(addr.ip().to_string());
    }
    Ok(ips)
}

#[derive(Clone)]
pub struct Service(pub k8s_openapi::api::core::v1::Service);

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

    pub async fn port_forward_rules(
        &self,
        unifi_interface: &str,
    ) -> Result<Vec<unifi::PortForwardRule>> {
        let service_identifier_base = self.get_service_identifier().ok_or(anyhow::anyhow!(
            "Skipping service {:?} due to missing namespace or name",
            self,
        ))?;

        let service_ips = self.get_external_ips().await?;

        let external_ip = service_ips
            .iter()
            .find(|ip_str| ip_str.parse::<IpAddr>().map_or(false, |ip| ip.is_ipv4()))
            .ok_or(anyhow::anyhow!(
                "Cannot create port forward rules for service '{:?}': external IP not found for service",
                self,
            ))?;

        let service_ports = self
            .0
            .spec
            .as_ref()
            .and_then(|spec| spec.ports.as_ref())
            .map_or_else(Vec::new, |ports| ports.clone());

        let mut rules = Vec::new();
        for service_port in service_ports {
            let protocol = service_port
                .protocol
                .as_ref()
                .map_or("tcp".to_string(), |p| p.to_string().to_lowercase());

            let full_identifier = format!(
                "{}/{}/{}",
                service_identifier_base, protocol, service_port.port
            );

            rules.push(unifi::PortForwardRule {
                id: None,
                name: full_identifier,
                enabled: true,
                pfwd_interface: unifi_interface.to_string(),
                fwd: external_ip.clone(),
                destination_ip: Some("any".to_string()),
                src: "any".to_string(),
                log: false,
                dst_port: serde_json::Value::String(service_port.port.to_string()),
                fwd_port: serde_json::Value::String(service_port.port.to_string()),
                proto: protocol,
                site_id: "".to_string(), // site_id is not known at this point
            });
        }
        Ok(rules)
    }

    pub async fn firewall_groups(&self) -> Result<Vec<unifi::FirewallGroup>> {
        let service_identifier_base = self.get_service_identifier().ok_or(anyhow::anyhow!(
            "Skipping service {:?} due to missing namespace or name",
            self,
        ))?;

        let service_ips = self.get_external_ips().await?;

        if service_ips.is_empty() {
            return Ok(Vec::new());
        }

        let (ipv4_ips, ipv6_ips): (Vec<String>, Vec<String>) = service_ips
            .into_iter()
            .partition(|ip_str| ip_str.parse::<IpAddr>().map_or(false, |ip| ip.is_ipv4()));

        let mut groups = Vec::new();

        if !ipv4_ips.is_empty() {
            groups.push(unifi::FirewallGroup {
                id: None,
                name: format!("{}-ipv4", service_identifier_base),
                description: Some(format!(
                    "Kubernetes managed firewall group for service {}",
                    service_identifier_base
                )),
                group_type: "address-group".to_string(),
                group_members: ipv4_ips,
                site_id: "".to_string(), // site_id is not known at this point
            });
        }

        if !ipv6_ips.is_empty() {
            groups.push(unifi::FirewallGroup {
                id: None,
                name: format!("{}-ipv6", service_identifier_base),
                description: Some(format!(
                    "Kubernetes managed firewall group for service {}",
                    service_identifier_base
                )),
                group_type: "ipv6-address-group".to_string(),
                group_members: ipv6_ips,
                site_id: "".to_string(), // site_id is not known at this point
            });
        }

        let service_ports: Vec<String> = self.get_service_ports();
        if !service_ports.is_empty() {
            groups.push(unifi::FirewallGroup {
                id: None,
                name: format!("{}-ports", service_identifier_base),
                description: Some(format!(
                    "Kubernetes managed firewall group for service {}",
                    service_identifier_base
                )),
                group_type: "port-group".to_string(),
                group_members: service_ports,
                site_id: "".to_string(), // site_id is not known at this point
            });
        }

        Ok(groups)
    }

    pub fn labels(&self) -> Option<&BTreeMap<std::string::String, std::string::String>> {
        self.0.metadata.labels.as_ref()
    }
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Customize the output here
        f.debug_struct("Service")
            .field("name", &self.0.metadata.name)
            .finish()
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        LoadBalancerIngress, LoadBalancerStatus, Service as K8sService, ServiceSpec, ServiceStatus,
    };
    use kube::api::ObjectMeta;

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
                .map(|p| k8s_openapi::api::core::v1::ServicePort {
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

    #[tokio::test]
    async fn test_get_service_identifier() {
        let k8s_service =
            create_test_k8s_service("my-service", "my-namespace", None, None, vec![], vec![]);
        let service = Service(k8s_service);
        assert_eq!(
            service.get_service_identifier(),
            Some("my-namespace/my-service".to_string())
        );
    }

    #[tokio::test]
    async fn test_get_external_ips() {
        let k8s_service = create_test_k8s_service(
            "my-service",
            "my-namespace",
            None,
            None,
            vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()],
            vec![],
        );
        let service = Service(k8s_service);
        assert_eq!(
            service.get_external_ips().await.unwrap(),
            vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()]
        );
    }

    #[tokio::test]
    async fn test_get_service_ports() {
        let k8s_service = create_test_k8s_service(
            "my-service",
            "my-namespace",
            None,
            None,
            vec![],
            vec![80, 443],
        );
        let service = Service(k8s_service);
        assert_eq!(
            service.get_service_ports(),
            vec!["80".to_string(), "443".to_string()]
        );
    }

    #[tokio::test]
    async fn test_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "my-app".to_string());
        let k8s_service = create_test_k8s_service(
            "my-service",
            "my-namespace",
            Some(labels.clone()),
            None,
            vec![],
            vec![],
        );
        let service = Service(k8s_service);
        assert_eq!(service.labels().unwrap(), &labels);
    }

    #[tokio::test]
    async fn test_port_forward_rules() {
        let k8s_service = create_test_k8s_service(
            "my-service",
            "my-namespace",
            None,
            None,
            vec!["192.168.1.1".to_string()],
            vec![80],
        );
        let service = Service(k8s_service);
        let rules = service.port_forward_rules("wan").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "my-namespace/my-service/tcp/80");
        assert_eq!(rules[0].fwd, "192.168.1.1");
    }

    #[tokio::test]
    async fn test_firewall_groups() {
        let k8s_service = create_test_k8s_service(
            "my-service",
            "my-namespace",
            None,
            None,
            vec!["192.168.1.1".to_string(), "2001:db8::1".to_string()],
            vec![80],
        );
        let service = Service(k8s_service);
        let groups = service.firewall_groups().await.unwrap();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].name, "my-namespace/my-service-ipv4");
        assert_eq!(groups[0].group_members, vec!["192.168.1.1".to_string()]);
        assert_eq!(groups[1].name, "my-namespace/my-service-ipv6");
        assert_eq!(groups[1].group_members, vec!["2001:db8::1".to_string()]);
        assert_eq!(groups[2].name, "my-namespace/my-service-ports");
        assert_eq!(groups[2].group_members, vec!["80".to_string()]);
    }
}
