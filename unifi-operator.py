#!/usr/bin/env python3

import argparse
import functools
import ipaddress
import json
import sys


import kubernetes
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class Unifi:
    REQUEST_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    def __init__(
        self,
        username,
        password,
        hostname,
        dry_run=False,
        site=None,
    ):
        self._csrf = None
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._base_url = f'https://{hostname}'
        self._dry_run = dry_run

        if not site:
            site = 'default'

        self._site = site

    def create_rule(self, rule, dry_run=False):
        if self._dry_run:
            print(
                'Would create port forward rule: {}'
                .format(json.dumps(rule, indent=2))
            )
            return True

        return self._query(self._session.post, 'rest/portforward', rule)

    def login(self):
        response = self._session.post(
            f'{self._base_url}/api/auth/login',
            headers=self.REQUEST_HEADERS,
            json={'username': self._username, 'password': self._password},
            verify=False,
        )

        self._csrf = response.headers['X-CSRF-Token']

        return self

    def rules(self):
        return self._session.get(
            self._endpoint('rest/portforward'),
            headers=REQUEST_HEADERS,
        ).json()['data']

    def update_rule(self, rule):
        rule_id = rule.pop('_id')

        if self._dry_run:
            print(
                'Would update port forward rule {rule_id}: {rule}'
                .format(rule_id=rule_id, rule=json.dumps(rule, indent=2))
            )
            return True

        return self._query(self._session.put, f'rest/portforward/{rule_id}', rule)

    def _endpoint(self, endpoint):
        return f'{self._base_url}/proxy/network/api/s/{self._site}/{endpoint}'

    def _query(self, method, endpoint, payload):
        return method(
            self._endpoint('rest/portforward'),
            headers=dict(self.REQUEST_HEADERS, **{'X-CSRF-TOKEN': self._csrf}),
            json=payload,
        )


def service_filter(service, label):
    if service.spec.type != 'LoadBalancer':
        return False

    labels = service.metadata.labels or {}

    if label not in labels:
        return False

    return True


def merge_rules(existing_rules, generated_rules):
    port_forward_rules ={
        port_configuration['dst_port']: port_configuration
        for port_configuration in existing_rules
    }

    new_rules = {}
    updated_rules = {}
    for port, configuration in generated_rules.copy().items():
        new_rule = generated_rules.pop(port)

        key = None
        str_port = str(port)

        if port in port_forward_rules:
            key = port
        if str_port in port_forward_rules:
            key = str_port

        if key:
            old_rule = port_forward_rules.pop(key)
            updated_rules[str_port] = dict(old_rule, **configuration)
            continue

        new_rules[port] = new_rule

    return new_rules, updated_rules


def generate_port_forward_rules(interface, services, filter_cb):
    rules = {}

    for service in services.items:
        if not filter_cb(service):
            continue

        for address in service.status.load_balancer.ingress:
            parsed_address = ipaddress.ip_address(address.ip)

            if parsed_address.version != 4:
                continue

            for port in service.spec.ports:
                if port.port in rules:
                    raise ValueError(f'Duplicate port encountered: {port.port}')

                protocol = port.protocol.lower()
                rules[port.port] = {
                    'name': f'{service.metadata.name}/{protocol}/{port.port}',
                    'pfwd_interface': interface,
                    'fwd': str(parsed_address),
                    'src': 'any',
                    'log': False,
                    'proto': protocol,
                    'dst_port': port.port,
                    'fwd_port': port.port,
                    'enabled': True,
                }

    return rules


def publish(unifi, generated_rules, no_create, no_update):
    result = True

    existing_rules = unifi.rules()

    port_forward_rules ={
        port_configuration['dst_port']: port_configuration
        for port_configuration in existing_rules
    }

    new_rules, updated_rules = merge_rules(
        existing_rules,
        generated_rules,
    )

    if not no_create:
        responses = [
            unifi.create_rule(rule)
            for rule in new_rules.values()
        ]

        result = result and all(responses)

    if not no_update:
        responses = [
            unifi.update_rule(rule)
            for rule in updated_rules.values()
        ]

        result = result and all(responses)

    return result


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument(
        '--label',
        default='io.github.craigcabrey/unifi-forward-ports',
    )
    parser.add_argument('--no-create', action='store_true')
    parser.add_argument('--no-update', action='store_true')

    kubernetes = parser.add_argument_group()
    kubernetes.add_argument('--local-cluster', action='store_true')

    unifi = parser.add_argument_group()
    unifi.add_argument('--unifi-interface', default='wan')
    unifi.add_argument('--unifi-hostname', default='unifi')
    unifi.add_argument('--unifi-username', required=True)
    unifi.add_argument('--unifi-password', required=True)
    unifi.add_argument('--unifi-sitename', default='default')
    unifi.add_argument('--unifi-insecure', action='store_true')

    return parser.parse_args()


def main():
    args = parse_args()

    if args.local_cluster:
        kubernetes.config.load_kube_config()
    else:
        kubernetes.config.load_incluster_config()

    if not args.unifi_insecure:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    base_url = f'https://{args.unifi_hostname}'
    network_url = f'{base_url}/proxy/network/api/s/{args.unifi_sitename}'
    credentials = {'username': args.unifi_username, 'password': args.unifi_password}

    with kubernetes.client.ApiClient() as client:
        v1 = kubernetes.client.CoreV1Api(client)
        services = v1.list_service_for_all_namespaces()
        generated_rules = generate_port_forward_rules(
            args.unifi_interface,
            services,
            functools.partial(service_filter, label=args.label),
        )

    unifi = Unifi(
        args.unifi_username,
        args.unifi_password,
        args.unifi_hostname,
        dry_run=args.dry_run,
        site=args.unifi_sitename,
    ).login()

    return publish(
        unifi,
        generated_rules,
        args.no_create,
        args.no_update,
    )


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
