#!/usr/bin/env python3

'''
Kubernetes operator/controller for managing
Unifi network devices, namely for forwarding
ports to LoadBalancer k8s services.
'''

import argparse
import enum
import functools
import ipaddress
import json
import logging
import os
import sys
import typing
import urllib3


import kubernetes  # type: ignore
import requests


logger = logging.getLogger(__name__)
logging.basicConfig(
    format='[{asctime}] {levelname:<8} {message}',
    style='{',
)
logger.setLevel(logging.INFO)


Rule = typing.Dict[str, typing.Union[str, bool]]
RuleSet = typing.Dict[str, Rule]


class EventType(enum.Enum):
    Added = 'ADDED'
    Deleted = 'DELETED'
    Modified = 'MODIFIED'


class ServiceType(enum.Enum):
    ClusterIP = 'ClusterIP'
    ExternalName = 'ExternalName'
    LoadBalancer = 'LoadBalancer'
    NodePort = 'NodePort'


class Service:
    def __init__(
        self, service: kubernetes.client.models.v1_service.V1Service
    ) -> None:
        self._service = service

    @property
    def addresses(
        self,
    ) -> typing.Generator[
        typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address], None, None
    ]:
        addresses = self._service.status.load_balancer.ingress or []

        for address in addresses:
            yield ipaddress.ip_address(address.ip)

    @property
    def identifier(self) -> str:
        return f'{self.namespace}/{self.name}'

    @property
    def labels(self) -> typing.Dict[str, str]:
        return self._service.metadata.labels or {}

    @property
    def name(self) -> str:
        return self._service.metadata.name

    @property
    def namespace(self) -> str:
        return self._service.metadata.namespace

    @property
    def ports(
        self,
    ) -> typing.List[kubernetes.client.models.v1_service_port.V1ServicePort]:
        return self._service.spec.ports

    @property
    def type(self) -> ServiceType:
        return ServiceType(self._service.spec.type)

    def merge_existing_port_forward_rules(
        self, existing_rules: RuleSet
    ) -> typing.Tuple[RuleSet, RuleSet]:
        new_rules = {}
        updated_rules = {}
        generated_rules = self.port_forward_rules()

        for name, rule in generated_rules.copy().items():
            if not name.startswith(self.identifier):
                continue

            new_rule = generated_rules.pop(name)

            if name in existing_rules:
                existing_rule = existing_rules.pop(name)
                updated_rules[name] = dict(existing_rule, **rule)
                continue

            new_rules[name] = new_rule

        return new_rules, updated_rules

    def port_forward_rules(self) -> RuleSet:
        rules = {}

        for address in self.addresses:
            if address.version != 4:
                continue

            for port in self.ports:
                name = '{identifier}/{protocol}/{port}'.format(
                    identifier=self.identifier,
                    protocol=port.protocol,
                    port=port.port,
                ).lower()

                rules[name] = {
                    'name': name,
                    'fwd': str(address),
                    'src': 'any',
                    'log': False,
                    'proto': port.protocol.lower(),
                    'dst_port': port.port,
                    'fwd_port': port.port,
                    'enabled': True,
                }

        return rules


class ServiceEvent:
    @classmethod
    def from_kubernetes_event(cls, event) -> typing.Self:
        return cls(
            EventType(event['type']),
            Service(event['object']),
        )

    def __init__(self, type: EventType, service: Service) -> None:
        self.type = type
        self.service = service


class Unifi:
    REQUEST_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    def __init__(
        self,
        username: str,
        password: str,
        hostname: str,
        dry_run: bool = False,
        site: typing.Optional[str] = None,
        wan_interface: typing.Optional[str] = None,
    ) -> None:
        self._csrf: typing.Optional[str] = None
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

    def create_port_forward_rule(self, rule: Rule) -> bool:
        rule['pfwd_interface'] = self._wan_interface

        if self._dry_run:
            logger.debug(
                'Would create port forward rule: %s',
                json.dumps(rule, indent=2),
            )
            return True

        logger.info('Creating new port forward rule: %s', rule)
        response = self._query(self._session.post, 'rest/portforward', rule)

        return response.ok

    def delete_port_forward_rule(self, rule: Rule) -> bool:
        rule_id = rule.pop('_id', None)

        if self._dry_run:
            logger.debug('Would delete port forward rule %s', rule_id)
            return True

        if not rule_id:
            logger.warn('Attempted to delete rule with an id: %s', rule)
            return False

        logger.info('Delete port forward rule: %s', rule_id)
        response = self._query(
            self._session.delete, f'rest/portforward/{rule_id}'
        )

        return response.ok

    def login(self) -> typing.Self:
        response = self._session.post(
            f'{self._base_url}/api/auth/login',
            headers=self.REQUEST_HEADERS,
            json={'username': self._username, 'password': self._password},
            verify=False,
        )

        self._csrf = response.headers['X-CSRF-Token']

        return self

    def get_port_forward_rules(self) -> RuleSet:
        return {
            rule['name']: rule
            for rule in self._query(
                self._session.get, 'rest/portforward'
            ).json()['data']
        }

    def update_port_forward_rule(self, rule: Rule) -> bool:
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
        response = self._query(
            self._session.put, f'rest/portforward/{rule_id}', rule
        )

        return response.ok

    def _endpoint(self, endpoint: str) -> str:
        return f'{self._base_url}/proxy/network/api/s/{self._site}/{endpoint}'

    def _query(
        self,
        method: typing.Callable,
        endpoint: str,
        payload: typing.Optional[typing.Any] = None,
    ) -> requests.models.Response:
        return method(
            self._endpoint(endpoint),
            headers=dict(self.REQUEST_HEADERS, **{'X-CSRF-TOKEN': self._csrf}),
            json=payload,
        )


def handle_event(event: ServiceEvent, label: str, unifi: Unifi) -> bool:
    result = True

    if label not in event.service.labels:
        logger.debug(
            'Ignoring event %s for service %s',
            event.type,
            event.service.name,
        )
        return True

    logger.info(
        'Handling event %s for service %s',
        event.type,
        event.service.name,
    )

    new_rules, updated_rules = event.service.merge_existing_port_forward_rules(
        unifi.get_port_forward_rules(),
    )

    if event.type == EventType.Deleted:
        result = all(
            [
                unifi.delete_port_forward_rule(rule)
                for rule in updated_rules.values()
            ]
        )
    else:
        create_responses = [
            unifi.create_port_forward_rule(rule) for rule in new_rules.values()
        ]

        update_responses = [
            unifi.update_port_forward_rule(rule)
            for rule in updated_rules.values()
        ]

        result = all(create_responses) and all(update_responses)

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(__doc__)

    parser.add_argument('--debug', action='store_true')
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Do not make any mutable changes (best effort)',
    )
    parser.add_argument(
        '--label',
        default='io.github.craigcabrey/unifi-forward-ports',
        help='Label on services to track for port forwards',
    )
    parser.add_argument(
        '--watch',
        action='store_true',
        help='Continue to watch for service events (act as an "operator")',
    )

    kubernetes = parser.add_argument_group('Kubernetes Configuration')
    kubernetes.add_argument(
        '--local-cluster',
        action='store_true',
        help='Use the config typically located in ~/.kube for cluster access',
    )

    unifi = parser.add_argument_group('Unifi Configuration')
    unifi.add_argument(
        '--unifi-interface',
        default='wan',
        help='Interface from which to setup port forwards',
    )
    unifi.add_argument(
        '--unifi-hostname',
        default='unifi',
        help='Hostname of the Unifi Dream Machine',
    )
    unifi.add_argument(
        '--unifi-sitename',
        default='default',
        help='Sitename in the Unifi Network application',
    )
    unifi.add_argument(
        '--unifi-insecure',
        action='store_true',
        help=(
            'Do not validate server certificate (Unifi equipment comes loaded '
            'with self-signed certificates)'
        ),
    )

    env_unifi_username = os.environ.get('UNIFI_OPERATOR_UNIFI_USERNAME')
    unifi.add_argument(
        '--unifi-username',
        default=env_unifi_username,
        required=not env_unifi_username,
        help=(
            'Username for API access (also settable via '
            'UNIFI_OPERATOR_UNIFI_USERNAME environment variable)'
        ),
    )

    env_unifi_password = os.environ.get('UNIFI_OPERATOR_UNIFI_PASSWORD')
    unifi.add_argument(
        '--unifi-password',
        default=env_unifi_password,
        required=not env_unifi_password,
        help=(
            'Password for API access (also settable via '
            'UNIFI_OPERATOR_UNIFI_PASSWORD environment variable)'
        ),
    )

    args = parser.parse_args()

    if args.debug or args.dry_run:
        logger.setLevel(logging.DEBUG)

    return args


def main() -> bool:
    args = parse_args()

    if args.local_cluster:
        kubernetes.config.load_kube_config()
    else:
        kubernetes.config.load_incluster_config()

    if args.unifi_insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
                    ServiceEvent.from_kubernetes_event(event),
                    args.label,
                    unifi,
                )
        except KeyboardInterrupt:
            break
        except urllib3.exceptions.ReadTimeoutError:
            if args.watch:
                raise
            else:
                break

    return True


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
