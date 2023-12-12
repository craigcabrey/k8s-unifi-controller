#!/usr/bin/env python3

import argparse
import enum
import functools
import ipaddress
import json
import logging
import os
import sys
import urllib3


import kubernetes
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


logger = logging.getLogger(__name__)
logging.basicConfig(
    format='[{asctime}] {levelname:<8} {message}',
    style='{',
)
logger.setLevel(logging.INFO)


class EventType(enum.Enum):
    Added = 'ADDED'
    Deleted = 'DELETED'
    Modified = 'MODIFIED'


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
        wan_interface=None,
    ):
        self._csrf = None
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._base_url = f'https://{hostname}'
        self._dry_run = dry_run

        if not site:
            site = 'default'

        if not wan_interface:
            wan_interface = 'wan'

        self._site = site
        self._wan_interface = wan_interface

    def create_port_forward_rule(self, rule):
        rule['pfwd_interface'] = self._wan_interface

        if self._dry_run:
            logger.debug(
                'Would create port forward rule: %s',
                json.dumps(rule, indent=2),
            )
            return True

        logger.info('Creating new port forward rule: %s', rule)
        return self._query(self._session.post, 'rest/portforward', rule)

    def delete_port_forward_rule(self, rule):
        rule_id = rule.pop('_id')

        if self._dry_run:
            logger.debug('Would delete port forward rule %s', rule_id)
            return True

        logger.info('Delete port forward rule: %s', rule_id)
        return self._query(self._session.delete, f'rest/portforward/{rule_id}')

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
            headers=self.REQUEST_HEADERS,
        ).json()['data']

    def update_port_forward_rule(self, rule):
        rule_id = rule.pop('_id')
        rule['pfwd_interface'] = self._wan_interface

        if self._dry_run:
            logger.debug(
                'Would update port forward rule %s: %s',
                rule_id,
                json.dumps(rule, indent=2),
            )
            return True

        logger.info('Updating port forward rule %s: %s', rule_id, rule)
        return self._query(self._session.put, f'rest/portforward/{rule_id}', rule)

    def _endpoint(self, endpoint):
        return f'{self._base_url}/proxy/network/api/s/{self._site}/{endpoint}'

    def _query(self, method, endpoint, payload=None):
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
    port_forward_rules = {
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


def generate_service_port_forward_rules(service):
    rules = {}

    for address in service.status.load_balancer.ingress:
        parsed_address = ipaddress.ip_address(address.ip)

        if parsed_address.version != 4:
            continue

        for port in service.spec.ports:
            if port.port in rules:
                raise ValueError(f'Duplicate port encountered: {port.port}')

            protocol = port.protocol.lower()
            rules[port.port] = {
                'name': '{namespace}/{name}/{protocol}/{port}'.format(
                    namespace=service.metadata.namespace,
                    name=service.metadata.name,
                    protocol=protocol,
                    port=port.port,
                ),
                'fwd': str(parsed_address),
                'src': 'any',
                'log': False,
                'proto': protocol,
                'dst_port': port.port,
                'fwd_port': port.port,
                'enabled': True,
            }

    return rules


def handle_event(event, label, unifi):
    result = True
    operation = EventType(event['type'])
    service = event['object']

    if not service_filter(service, label):
        logger.debug(
            'Ignoring new event %s for service %s',
            operation,
            service.metadata.name,
        )
        return False

    logger.info(
        'Handling new event %s for service %s',
        operation,
        service.metadata.name,
    )

    new_rules, updated_rules = merge_rules(
        unifi.rules(),
        generate_service_port_forward_rules(
            service,
        ),
    )

    if operation == EventType.Deleted:
        result = all([
            unifi.delete_port_forward_rule(rule)
            for rule in updated_rules.values()
        ])
    else:
        create_responses = [
            unifi.create_port_forward_rule(rule)
            for rule in new_rules.values()
        ]

        update_responses = [
            unifi.update_port_forward_rule(rule)
            for rule in updated_rules.values()
        ]

        result = all(create_responses) and all(update_responses)

    return result


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument(
        '--label',
        default='io.github.craigcabrey/unifi-forward-ports',
    )
    parser.add_argument(
        '--watch',
        action='store_true',
        help='Continue to watch for service events (act as an "operator")',
    )

    kubernetes = parser.add_argument_group()
    kubernetes.add_argument('--local-cluster', action='store_true')

    unifi = parser.add_argument_group()
    unifi.add_argument('--unifi-interface', default='wan')
    unifi.add_argument('--unifi-hostname', default='unifi')
    unifi.add_argument('--unifi-sitename', default='default')
    unifi.add_argument('--unifi-insecure', action='store_true')

    env_unifi_username = os.environ.get('UNIFI_OPERATOR_UNIFI_USERNAME')
    unifi.add_argument(
        '--unifi-username',
        default=env_unifi_username,
        required=not env_unifi_username,
    )

    env_unifi_password = os.environ.get('UNIFI_OPERATOR_UNIFI_PASSWORD')
    unifi.add_argument(
        '--unifi-password',
        default=env_unifi_password,
        required=not env_unifi_password,
    )

    args = parser.parse_args()

    if args.debug or args.dry_run:
        logger.setLevel(logging.DEBUG)

    return args


def main():
    args = parse_args()

    if args.local_cluster:
        kubernetes.config.load_kube_config()
    else:
        kubernetes.config.load_incluster_config()

    if args.unifi_insecure:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    v1 = kubernetes.client.CoreV1Api()
    unifi = Unifi(
        args.unifi_username,
        args.unifi_password,
        args.unifi_hostname,
        dry_run=args.dry_run,
        site=args.unifi_sitename,
        wan_interface=args.unifi_interface,
    ).login()

    while True:
        try:
            for event in kubernetes.watch.Watch().stream(
                v1.list_service_for_all_namespaces,
                _request_timeout=None if args.watch else 5,
            ):
                result = handle_event(
                    event,
                    args.label,
                    unifi,
                )
        except KeyboardInterrupt:
            break
        except urllib3.exceptions.ReadTimeoutError:
            break

    return True


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
