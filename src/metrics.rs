use lazy_static::lazy_static;
use log::info;
use prometheus::{Encoder, IntCounter, TextEncoder, opts, register_int_counter};
use std::net::IpAddr;
use warp::Filter;

lazy_static! {
    pub static ref SERVICES_SEEN_TOTAL: IntCounter = register_int_counter!(opts!(
        "services_seen_total",
        "Total number of services seen by the controller"
    ))
    .unwrap();
    pub static ref SERVICES_PROCESSED_TOTAL: IntCounter = register_int_counter!(opts!(
        "services_processed_total",
        "Total number of services processed by the controller (having relevant labels)"
    ))
    .unwrap();
    pub static ref PORT_FORWARD_UPDATES_TOTAL: IntCounter = register_int_counter!(opts!(
        "port_forward_updates_total",
        "Total number of port forward updates attempted"
    ))
    .unwrap();
    pub static ref PORT_FORWARD_UPDATE_FAILURES_TOTAL: IntCounter = register_int_counter!(opts!(
        "port_forward_update_failures_total",
        "Total number of failed port forward updates"
    ))
    .unwrap();
    pub static ref PORT_FORWARD_CREATIONS_TOTAL: IntCounter = register_int_counter!(opts!(
        "port_forward_creations_total",
        "Total number of port forward creations attempted"
    ))
    .unwrap();
    pub static ref PORT_FORWARD_CREATION_FAILURES_TOTAL: IntCounter = register_int_counter!(opts!(
        "port_forward_creation_failures_total",
        "Total number of failed port forward creations"
    ))
    .unwrap();
    pub static ref PORT_FORWARD_DELETIONS_TOTAL: IntCounter = register_int_counter!(opts!(
        "port_forward_deletions_total",
        "Total number of port forward deletions attempted"
    ))
    .unwrap();
    pub static ref PORT_FORWARD_DELETION_FAILURES_TOTAL: IntCounter = register_int_counter!(opts!(
        "port_forward_deletion_failures_total",
        "Total number of failed port forward deletions"
    ))
    .unwrap();
    pub static ref FIREWALL_GROUP_UPDATES_TOTAL: IntCounter = register_int_counter!(opts!(
        "firewall_group_updates_total",
        "Total number of firewall group updates attempted"
    ))
    .unwrap();
    pub static ref FIREWALL_GROUP_UPDATE_FAILURES_TOTAL: IntCounter = register_int_counter!(opts!(
        "firewall_group_update_failures_total",
        "Total number of failed firewall group updates"
    ))
    .unwrap();
    pub static ref FIREWALL_GROUP_CREATIONS_TOTAL: IntCounter = register_int_counter!(opts!(
        "firewall_group_creations_total",
        "Total number of firewall group creations attempted"
    ))
    .unwrap();
    pub static ref FIREWALL_GROUP_CREATION_FAILURES_TOTAL: IntCounter =
        register_int_counter!(opts!(
            "firewall_group_creation_failures_total",
            "Total number of failed firewall group creations"
        ))
        .unwrap();
    pub static ref FIREWALL_GROUP_DELETIONS_TOTAL: IntCounter = register_int_counter!(opts!(
        "firewall_group_deletions_total",
        "Total number of firewall group deletions attempted"
    ))
    .unwrap();
    pub static ref FIREWALL_GROUP_DELETION_FAILURES_TOTAL: IntCounter =
        register_int_counter!(opts!(
            "firewall_group_deletion_failures_total",
            "Total number of failed firewall group deletions"
        ))
        .unwrap();
    pub static ref RECONCILIATIONS_TOTAL: IntCounter = register_int_counter!(opts!(
        "reconciliations_total",
        "Total number of reconciliations"
    ))
    .unwrap();
    pub static ref RECONCILIATION_FAILURES_TOTAL: IntCounter = register_int_counter!(opts!(
        "reconciliation_failures_total",
        "Total number of failed reconciliations"
    ))
    .unwrap();
}

pub async fn metrics_server(host: String, port: u16) {
    let addr: IpAddr = host.parse().expect("Invalid metrics host address");
    let socket_addr = std::net::SocketAddr::new(addr, port);

    let metrics = warp::path!("metrics").and(warp::get()).map(|| {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        warp::reply::with_header(
            String::from_utf8(buffer).unwrap(),
            "content-type",
            "text/plain; version=0.0.4",
        )
    });

    info!("Starting metrics server on {}", socket_addr);
    warp::serve(metrics).run(socket_addr).await;
}
