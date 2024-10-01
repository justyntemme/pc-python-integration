# Installed
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from queue import Queue
from threading import Thread
import time
from typing import Any, Dict, Tuple

import requests
from urllib3.exceptions import InsecureRequestWarning

from ._cspm_session import CSPMSession
from ._session_base import Session


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Local

WORKER_THREADS = 6


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
class SaaSCWPSession(Session):
    def __init__(
        self,
        tenant_name: str,
        a_key: str,
        s_key: str,
        api_url: str,
        verify: bool,
        proxies: dict,
        logger,
        cspm_session={},
    ):
        """
        Initializes a Prisma Cloud API session for a given tenant.

        Keyword Arguments:
        tenant_name -- Name of tenant associated with session
        a_key -- Tenant Access Key
        s_key -- Tenant Secret Key
        api_url -- API URL Tenant is hosted on
        """

        super().__init__(logger)

        self.tenant = tenant_name
        self.a_key = a_key
        self.s_key = s_key
        self.api_url = api_url
        self.verify = verify
        self.proxies = proxies

        self.token_time_stamp = 0

        self.logger = logger

        self.cspm_session = {}
        self.cspm_token = ""

        if not cspm_session:
            self.__get_cspm_session()
        else:
            self.cspm_session = cspm_session
            self.cspm_token = self.cspm_session.token

        # self.api_url = self.__cwpp_metadata(self.cspm_session)

        self.auth_key = "Authorization"
        self.auth_style = "Bearer "

        self.token = ""
        self.request_queue = Queue()
        self.output_queue = Queue()
        self.container_open_ports = []

        self.headers = {
            "content-type": "application/json; charset=UTF-8",
            "Authorization": "Bearer ",
        }

        self._api_login_wrapper()

    # ==============================================================================
    def __get_cspm_session(self):
        self.cspm_session = CSPMSession(
            self.tenant,
            self.a_key,
            self.s_key,
            self.api_url,
            self.verify,
            self.proxies,
            self.logger,
        )
        self.cspm_token = self.cspm_session.token

        # ==============================================================================

    def _api_login(self) -> object:
        """
        Calls the Prisma Cloud API to generate a x-redlock-auth JWT.

        Returns:
        x-redlock-auth JWT.
        """

        # Build request
        url = f"{self.api_url}/api/v1/authenticate"
        self.logger.debug(f"api url {self.api_url}")
        headers = {"content-type": "application/json; charset=UTF-8"}

        payload = {
            "username": self.a_key,
            "password": self.s_key,
            # "token": self.cspm_token,
        }

        self.logger.debug(
            f"API - Generating SaaS CWPP session token. payload value {payload}"
        )

        res = object()
        try:
            start_time = time.time()
            self.logger.debug("_api_login calling %s", url)
            res = requests.request(
                "POST",
                url,
                headers=headers,
                json=payload,
                verify=self.verify,
                proxies=self.proxies,
            )
            data = res.json()
            self.cwp_token = data["token"]
            end_time = time.time()
            time_completed = round(end_time - start_time, 3)

            self.token_time_stamp = time.time()
        except:
            self.logger.error("Failed to connect to API.")
            self.logger.warning("Make sure any offending VPNs are disabled.")

        return [res, time_completed]

    def _expired_login(self) -> None:
        self.logger.warning("CWP session expired. Generating new session.")
        self._api_login()

    def _api_refresh(self) -> None:
        # res, time = self._api_login(self)

        self.logger.debug(
            "API - Refreshing SaaS CWP session token _saas_cpw_session.py."
        )
        return self._api_login()

    def _get__container_network_info(self, offset, limit) -> Tuple[int, str]:
        url = f"{self.api_url}/api/v1/containers"
        self.logger.debug(f"api url {url}")

        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

        params = {"offset": offset, "limit": limit}

        response = requests.get(
            url, headers=headers, params=params, timeout=60, verify=False
        )

        return response.status_code, response.text

    def _container_producer(self):
        offset = 0
        limit = 100
        request_count = 0
        start_time = time.time()
        RATE_LIMIT = 30
        RATE_LIMIT_PERIOD = 30  # seconds
        while True:
            # Implement rate limiting
            if request_count >= RATE_LIMIT:
                elapsed_time = time.time() - start_time
                if elapsed_time < RATE_LIMIT_PERIOD:
                    sleep_time = RATE_LIMIT_PERIOD - elapsed_time
                    self.logger.info(
                        f"Rate limit reached. Sleeping for {sleep_time} seconds..."
                    )
                    time.sleep(sleep_time)
                request_count = 0
                start_time = time.time()

            status_code, response_text = self._get__container_network_info(
                offset, limit
            )
            request_count += 1

            if status_code != 200:
                self.logger.error(f"Error fetching containers: {status_code}")
                break

            containers = json.loads(response_text)
            if not containers:
                break  # No more data to fetch

            for container in containers:
                self.request_queue.put(container)

            if len(containers) < limit:
                break  # Last page has fewer items, we're done

            offset += limit

        # Indicate that no more data will be sent
        for _ in range(WORKER_THREADS):
            self.request_queue.put(None)

    def _container_consumer(self):
        while True:
            container = self.request_queue.get()
            if container is None:
                break

            container_info = self._extract_network_info(container)
            if container_info:
                self.output_queue.put(container_info)

            self.request_queue.task_done()

        # Indicate that no more data will be processed
        self.output_queue.put(None)

    def get_open_container_ports(self) -> object:
        producer_thread = Thread(target=self._container_producer)
        producer_thread.start()

        output_thread = Thread(target=self._container_outputter)
        output_thread.start()

        # Start the worker threads
        worker_threads = []
        for _ in range(WORKER_THREADS):
            worker_thread = Thread(target=self._container_consumer)
            worker_threads.append(worker_thread)
            worker_thread.start()

        # Wait for the producer thread to complete
        producer_thread.join()

        # Wait for the worker threads to complete
        for worker_thread in worker_threads:
            worker_thread.join()

        # Indicate to the output thread that processing is complete
        self.output_queue.put(None)

        # Wait for the output thread to complete
        output_thread.join()
        return self.container_open_ports

    def _container_outputter(self):
        while True:
            container_info = self.output_queue.get()
            if container_info is None:
                break
            self.container_open_ports.append(json.dumps(container_info, indent=2))
            self.logger.debug("Found network info object")
            # print(json.dumps(container_info, indent=2))  # Use print for output
            self.output_queue.task_done()

    def _extract_network_info(self, container: Dict[str, Any]) -> Dict[str, Any]:
        container_id = container.get("_id")

        open_ports = []

        # Extract ports from `network` object
        network = container.get("network", {})
        network_ports = network.get("ports", [])
        for port in network_ports:
            open_ports.append(
                {
                    "port": port.get("container"),
                    "host_port": port.get("host"),
                    "host_ip": port.get("hostIP"),
                    "nat": port.get("nat"),
                    "type": "network",
                }
            )

        # Extract ports from `networkSettings` object
        network_settings = container.get("networkSettings", {})
        settings_ports = network_settings.get("ports", [])
        for port in settings_ports:
            open_ports.append(
                {
                    "port": port.get("containerPort"),
                    "host_port": port.get("hostPort"),
                    "host_ip": port.get("hostIP"),
                    "type": "networkSettings",
                }
            )

        # Extract ports from `firewallProtection` object
        firewall_protection = container.get("firewallProtection", {})
        fw_ports = firewall_protection.get("ports", [])
        for port in fw_ports:
            open_ports.append({"port": port, "type": "firewallProtection"})
        tls_ports = firewall_protection.get("tlsPorts", [])
        for port in tls_ports:
            open_ports.append({"port": port, "type": "firewallProtection_tls"})
        unprotected_processes = firewall_protection.get("unprotectedProcesses", [])
        for process in unprotected_processes:
            open_ports.append(
                {
                    "port": process.get("port"),
                    "process": process.get("process"),
                    "tls": process.get("tls"),
                    "type": "unprotectedProcess",
                }
            )

        if open_ports:
            container_network_info = {
                "id": container_id,
                "open_ports": open_ports,
                "network": network,
                "networks": network_settings,
            }
            return container_network_info

        return {}
