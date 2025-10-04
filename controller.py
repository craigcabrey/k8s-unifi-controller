#!/usr/bin/env python3

'''
Kubernetes controller for managing
Unifi network devices, namely for forwarding
ports to LoadBalancer k8s services.
'''

import argparse
import enum
import functools
import ipaddress
import itertools
import json
import logging
import os
import queue
import sys
import threading
import typing


import kubernetes  # type: ignore
import requests
import urllib3


logger = logging.getLogger(__name__)
logging.basicConfig(
    format='[{asctime}] {levelname:<8} {message}',
    style='{',
)
logger.setLevel(logging.INFO)


PartialPortForwardRule = typing.Dict[str, str]
PortForwardRule = typing.Dict[str, typing.Union[str, bool]]
PortForwardRuleSet = typing.Dict[str, PortForwardRule]


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
    ) -> typing.Iterable[
        typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ]:
        return map(
            lambda a: ipaddress.ip_address(a),
            filter(
                None,
                itertools.chain(
                    map(
                        lambda a: a.ip,
                        self._service.status.load_balancer.ingress or [],
                    ),
                    [self._service.spec.external_name],
                )
            )
        )

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
    ) -> typing.Iterable[
        kubernetes.client.models.v1_service_port.V1ServicePort
    ]:
        return self._service.spec.ports

    @property
    def type(self) -> ServiceType:
        return ServiceType(self._service.spec.type)

    def update_port_forward_rules(
        self, rules: PortForwardRuleSet
    ) -> typing.Tuple[
        typing.Iterable[PortForwardRule], typing.Iterable[PortForwardRule]
    ]:
        existing_service_rules = {
            name: rule
            for name, rule in rules.items()
            if name.startswith(self.identifier)
        }
        updated_rules = map(
            lambda r: dict(existing_service_rules.pop(r['name'], r), **r),
            self.port_forward_rules(),
        )

        return updated_rules, existing_service_rules.values()

    def port_forward_rules(self) -> typing.Iterable[PartialPortForwardRule]:
        return map(
            lambda item: {
                'name': f'{self.identifier}/{item[0].protocol}/{item[0].port}'.lower(),
                'fwd': str(item[1]),
                'src': 'any',
                'proto': item[0].protocol.lower(),
                'dst_port': item[0].port,
                'fwd_port': item[0].port,
            },
            filter(
                lambda item: item[1].version == 4,
                itertools.product(self.ports, self.addresses),
            ),
        )


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
    DEFAULT_REQUEST_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    def __init__(
        self,
        token: str,
        hostname: str,
        dry_run: bool = False,
        site: typing.Optional[str] = None,
        verify: bool = True,
        wan_interface: typing.Optional[str] = None,
    ) -> None:
        self._session = requests.Session()
        self._base_url = f'https://{hostname}'
        self._dry_run = dry_run
        self._request_headers = dict(
            self.DEFAULT_REQUEST_HEADERS,
            **{'X-API-KEY': token},
        )

        if not site:
            site = 'default'

        if not wan_interface:
            wan_interface = 'wan'

        self._site = site
        self._verify = verify
        self._wan_interface = wan_interface

    def create_port_forward_rule(self, rule: PortForwardRule) -> bool:
        if self._dry_run:
            logger.debug(
                'Would create port forward rule: %s',
                json.dumps(rule, indent=2),
            )
            return True

        logger.info('Creating new port forward rule: %s', rule)
        response = self._query(self._session.post, 'rest/portforward', rule)

        return response.ok

    def create_or_update_port_forward_rule(self, rule: PortForwardRule) -> bool:
        fn = self.create_port_forward_rule

        if '_id' in rule:
            fn = self.update_port_forward_rule

        rule = dict(
            rule, enabled=True, log=False, pfwd_interface=self._wan_interface
        )

        return fn(rule)

    def delete_port_forward_rule(self, rule: PortForwardRule) -> bool:
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

    def get_port_forward_rules(self) -> PortForwardRuleSet:
        return {
            rule['name']: rule
            for rule in self._query(
                self._session.get, 'rest/portforward'
            ).json()['data']
        }

    def update_port_forward_rule(self, rule: PortForwardRule) -> bool:
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
        response = method(
            self._endpoint(endpoint),
            headers=self._request_headers,
            json=payload,
            verify=self._verify,
        )

        if self._dry_run:
            logger.debug(response.json())

        return response


class EventManager:
    def __init__(
        self,
        *,
        core_api: typing.Optional[kubernetes.client.CoreV1Api] = None,
        event_queue: typing.Optional[queue.Queue] = None,
        generator_thread: typing.Optional[threading.Thread] = None,
        handler_thread: typing.Optional[threading.Thread] = None,
        label: typing.Optional[str] = None,
        unifi: Unifi,
        watch: bool = False,
    ) -> None:
        if not core_api:
            core_api = kubernetes.client.CoreV1Api()

        if not generator_thread:
            generator_thread = threading.Thread(target=self._generator)

        if not handler_thread:
            handler_thread = threading.Thread(target=self._handler)

        if not event_queue:
            event_queue = queue.Queue()

        self.core_api = core_api
        self.event_queue: queue.Queue = event_queue
        self.unifi = unifi

        self._event_stream = self._watch_stub
        self._generator_thread = generator_thread
        self._handler_thread = handler_thread
        self._label = label
        self._running = False
        self._watch = None

        if watch:
            self._init_watch()

    def start(self) -> typing.Self:
        self._running = True

        self._generator_thread.start()
        self._handler_thread.start()

        return self

    def stop(self, *_) -> None:
        self._running = False

        if self._watch:
            self._watch.stop()
            logger.debug('And now my watch has ended.')

        self.wait()

    def wait(self) -> None:
        self._generator_thread.join()
        self._handler_thread.join()

    def _generator(self) -> None:
        while self._running:
            try:
                logger.info('Starting event loop')

                for event in self._event_stream():
                    self.event_queue.put(
                        ServiceEvent.from_kubernetes_event(event), block=False
                    )
            except kubernetes.client.rest.ApiException:
                logger.info('Kubernetes watch expired, re-creating')
                self._init_watch()

        logger.info('Generator finished!')

    def _handle(self, event: ServiceEvent) -> None:
        if self._label and self._label not in event.service.labels:
            logger.debug(
                'Ignoring event %s for service %s with labels %s',
                event.type,
                event.service.name,
                event.service.labels,
            )
            return

        logger.info(
            'Handling event %s for service %s',
            event.type,
            event.service.name,
        )

        updated_rules, removed_rules = event.service.update_port_forward_rules(
            self.unifi.get_port_forward_rules(),
        )

        if event.type == EventType.Deleted:
            removed_rules = filter(
                lambda r: '_id' in r,
                itertools.chain(updated_rules, removed_rules),
            )
            updated_rules = []

        updated = all(
            map(self.unifi.create_or_update_port_forward_rule, updated_rules)
        )
        deleted = all(map(self.unifi.delete_port_forward_rule, removed_rules))

        logger.info(
            'Finished handling event %s for service %s with result %s',
            event.type,
            event.service.name,
            updated and deleted,
        )

    def _handler(self) -> None:
        while self._running:
            event = self.event_queue.get()

            if not event:
                self.event_queue.task_done()
                break

            self._handle(event)
            self.event_queue.task_done()

        try:
            while not self.event_queue.empty():
                event = self.event_queue.get(block=False)
                self._handle(event)
                self.event_queue.task_done()
        except queue.Empty:
            pass

        logger.info('Handler finished!')

    def _init_watch(self) -> None:
        self._watch = kubernetes.watch.Watch()
        self._event_stream = functools.partial(
            self._watch.stream,
            self.core_api.list_service_for_all_namespaces,
        )

    def _watch_stub(self) -> None:
        for service in self.core_api.list_service_for_all_namespaces().items:
            yield {
                'object': service,
                'type': 'ADDED',
            }

        self._running = False


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
        help='Continue to watch for service events (act as an "controller")',
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

    env_unifi_token = os.environ.get('UNIFI_OPERATOR_UNIFI_TOKEN')
    unifi.add_argument(
        '--unifi-token',
        default=env_unifi_token,
        required=not env_unifi_token,
        help=(
            'Token for API access (also settable via '
            'UNIFI_OPERATOR_UNIFI_TOKEN environment variable)'
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

    unifi = Unifi(
        args.unifi_token,
        args.unifi_hostname,
        dry_run=args.dry_run,
        site=args.unifi_sitename,
        verify=not args.unifi_insecure,
        wan_interface=args.unifi_interface,
    )

    event_queue: queue.Queue = queue.Queue()
    manager = EventManager(
        event_queue=event_queue,
        label=args.label,
        unifi=unifi,
        watch=args.watch,
    ).start()

    try:
        manager.wait()
    except KeyboardInterrupt:
        logger.info('Stop requested!')
        event_queue.put(None)
        manager.stop()
    finally:
        logger.info('Waiting for queue to finalize')
        event_queue.join()
        logger.info('Finished')

    return True


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
