# Installed
import requests
import json
from urllib3.exceptions import InsecureRequestWarning
from typing import Tuple, Dict, Any

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Local
from ._session_base import Session
from ._cspm_session import CSPMSession

# Python Library
import time


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

    def __cspm_login(self):
        self.cspm_token = self.cspm_session._api_login_wrapper()

    def __cwpp_metadata(self, cspm_session):
        res = cspm_session.request("GET", "meta_info")
        print(res)
        compute_url = res.json()["twistlockUrl"]

        return compute_url

    # ==============================================================================
    def _api_login(self) -> object:
        """
        Calls the Prisma Cloud API to generate a x-redlock-auth JWT.

        Returns:
        x-redlock-auth JWT.
        """

        # Build request
        url = f"{self.api_url}/api/v1/authenticate"
        self.logger.debug("api url %s", self.api_url)
        headers = {"content-type": "application/json; charset=UTF-8"}

        payload = {
            "username": self.a_key,
            "password": self.s_key,
            # "token": self.cspm_token,
        }

        self.logger.debug(
            "API - Generating SaaS CWPP session token. payload value %s", payload
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

    def _container_network_info(self) -> requests.Response:
        url = f"{self.api_url}/api/v1/containers"
        self.logger.debug("api url %s", self.api_url)

        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

        response = requests.get(url, headers=headers, timeout=60, verify=False)

        return response

    def get_open_container_ports(self) -> object:
        res = self._container_network_info()
        self.logger.debug(res.status_code)
        containers_array = json.loads(res.text)
        self.logger.debug(len(containers_array))
        for container in containers_array:
            output = self._extract_network_info(container)
            self.logger.debug(output)

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
            container_info = {
                "id": container_id,
                "open_ports": open_ports,
                "network": network,
                "networks": network_settings,
            }
            return container_info

        return {}
