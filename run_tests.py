import unittest
from unittest import mock
from unittest import TestCase
import os
import json

# Default Logger
import logging

logging.basicConfig()
py_logger = logging.getLogger("pcpi")
py_logger.setLevel(10)


# HELPER FUNCTIONS==============================================================
def load_environment():
    cfg = {}
    with open("local.json", "r") as file:
        cfg = json.load(file)

    # Parse cfg for tenant creds and set env
    for index, cred in enumerate(cfg):
        tenant = cred["name"]
        uname = cred["identity"]
        passwd = cred["secret"]
        api_url = cred["url"]
        tl_url = cred["tl_url"]
        verify = True
        try:
            verify = cred["verify"]
            if verify.lower() == "false":
                verify = False
            if verify.lower() == "true":
                verify = True
        except:
            pass

        proxies = cred["proxies"]
        https_proxy = ""
        http_proxy = ""
        if proxies:
            http_proxy = proxies.get("http", "")
            https_proxy = proxies.get("https", "")

        os.environ[f"PC_TENANT_NAME{index}"] = tenant
        os.environ[f"PC_TENANT_API{index}"] = api_url
        os.environ[f"PC_TENANT_TL_API{index}"] = tl_url
        os.environ[f"PC_TENANT_A_KEY{index}"] = uname
        os.environ[f"PC_TENANT_S_KEY{index}"] = passwd
        os.environ[f"PC_TENANT_VERIFY{index}"] = str(verify)
        os.environ[f"PC_HTTP_PROXY{index}"] = http_proxy
        os.environ[f"PC_HTTPS_PROXY{index}"] = https_proxy


# UNIT TESTS====================================================================


class credentialFileTests(TestCase):
    def testLoadConfigBasic(self):
        load_environment()
        from src.pcpi import session_loader
        from src.pcpi import saas_session_manager

        name = os.environ["PC_TENANT_NAME0"]
        api_url = os.environ["PC_TENANT_API0"]
        a_key = os.environ["PC_TENANT_A_KEY0"]
        s_key = os.environ["PC_TENANT_S_KEY0"]
        verify = os.environ["PC_TENANT_VERIFY0"]
        http = os.environ["PC_HTTP_PROXY0"]
        https = os.environ["PC_HTTPS_PROXY0"]
        proxies = {"http": http, "https": https}

        result = session_loader.load_config()
        self.assertEqual(
            [result[0].tenant],
            [
                saas_session_manager.SaaSSessionManager(
                    name, a_key, s_key, api_url, verify, proxies, py_logger
                ).tenant
            ],
        )
        self.assertEqual(
            [result[0].a_key],
            [
                saas_session_manager.SaaSSessionManager(
                    name, a_key, s_key, api_url, verify, proxies, py_logger
                ).a_key
            ],
        )
        self.assertEqual(
            [result[0].s_key],
            [
                saas_session_manager.SaaSSessionManager(
                    name, a_key, s_key, api_url, verify, proxies, py_logger
                ).s_key
            ],
        )
        self.assertEqual(
            [result[0].api_url],
            [
                saas_session_manager.SaaSSessionManager(
                    name, a_key, s_key, api_url, verify, proxies, py_logger
                ).api_url
            ],
        )

    def testLoadConfigEnv(self):
        load_environment()
        from src.pcpi import session_loader
        from src.pcpi import saas_session_manager

        name = os.environ["PC_TENANT_NAME0"]
        api_url = os.environ["PC_TENANT_API0"]
        a_key = os.environ["PC_TENANT_A_KEY0"]
        s_key = os.environ["PC_TENANT_S_KEY0"]
        verify = os.environ["PC_TENANT_VERIFY0"]
        http = os.environ["PC_HTTP_PROXY0"]
        https = os.environ["PC_HTTPS_PROXY0"]
        proxies = {"http": http, "https": https}

        result = session_loader.load_config_env(
            prisma_name="PC_TENANT_NAME0",
            identifier_name="PC_TENANT_A_KEY0",
            secret_name="PC_TENANT_S_KEY0",
            api_url_name="PC_TENANT_API0",
            verify_name="PC_TENANT_VERIFY0",
            http_name="PC_HTTP_PROXY0",
            https_name="PC_HTTPS_PROXY0",
        )
        self.assertEqual(
            result.tenant,
            saas_session_manager.SaaSSessionManager(
                name, a_key, s_key, api_url, verify, proxies, py_logger
            ).tenant,
        )
        self.assertEqual(
            result.a_key,
            saas_session_manager.SaaSSessionManager(
                name, a_key, s_key, api_url, verify, proxies, py_logger
            ).a_key,
        )
        self.assertEqual(
            result.s_key,
            saas_session_manager.SaaSSessionManager(
                name, a_key, s_key, api_url, verify, proxies, py_logger
            ).s_key,
        )
        self.assertEqual(
            result.api_url,
            saas_session_manager.SaaSSessionManager(
                name, a_key, s_key, api_url, verify, proxies, py_logger
            ).api_url,
        )


class apiRequestTest(TestCase):
    def testCSPMRecovery(self):
        from src.pcpi import session_loader

        manager = session_loader.load_config("local.json")[0]
        cspm_session = manager.create_cspm_session()
        res = cspm_session.request("GET", "/cloud")
        cspm_session.headers = {
            "content-type": "application/json; charset=UTF-8",
            "x-redlock-auth": "asd",
        }
        res1 = cspm_session.request("GET", "/cloud")

        self.assertEqual(res.json(), res1.json())

    def testCWPRecovery(self):
        from src.pcpi import session_loader

        manager = session_loader.load_config("local.json")[0]
        cwp_session = manager.create_cwp_session()
        res = cwp_session.request("GET", "/api/v1/users")
        cwp_session.headers = {
            "content-type": "application/json; charset=UTF-8",
            "Authorization": "Bearer dfsdfsd",
        }
        cwp_session.cspm_token = "sdfsdf"
        res1 = cwp_session.request("GET", "/api/v1/users")

        self.assertEqual(res.json(), res1.json())

    def testCertBypass(self):
        from src.pcpi import session_loader

        manager = session_loader.load_config("local.json")[0]
        cspm_session = manager.create_cspm_session()
        res = cspm_session.request("GET", "/cloud", verify=False)

        self.assertEqual(res.status_code, 200)

    # def testCertOverwrite(self):
    #     from src.pcpi import session_loader
    #     manager = session_loader.load_from_file()
    #     cspm_session = manager.create_cspm_session()
    #     res = cspm_session.request('GET', '/compliance', verify='globalprotect_certifi.txt')

    #     self.assertEqual(res.status_code, 200)


class SaaSCWPSessionTests(TestCase):
    @mock.patch("requests.request")
    def test_api_login_success(self, mock_request):
        from src.pcpi import saas_session_manager

        mock_response = mock.Mock()
        mock_response.json.return_value = {"token": "fake_token"}
        mock_request.return_value = mock_response

        session = saas_session_manager.SaaSCWPSession(
            tenant_name="test_tenant",
            a_key="test_a_key",
            s_key="test_s_key",
            api_url="https://test.api.url",
            verify=False,
            proxies={},
            logger=py_logger,
        )

        response, time_completed = session._api_login()

        self.assertEqual(session.cwp_token, "fake_token")
        self.assertIsInstance(response, mock.Mock)
        self.assertGreaterEqual(time_completed, 0)

    @mock.patch("requests.get")
    def test_get__container_network_info(self, mock_get):
        from src.pcpi import saas_session_manager

        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps([{"_id": "container1"}, {"_id": "container2"}])
        mock_get.return_value = mock_response

        session = saas_session_manager.SaaSCWPSession(
            tenant_name="test_tenant",
            a_key="test_a_key",
            s_key="test_s_key",
            api_url="https://test.api.url",
            verify=False,
            proxies={},
            logger=py_logger,
        )

        status_code, response_text = session._get__container_network_info(0, 100)

        self.assertEqual(status_code, 200)
        self.assertEqual(
            json.loads(response_text), [{"_id": "container1"}, {"_id": "container2"}]
        )

    @mock.patch("requests.get")
    def test_get_open_container_ports(self, mock_get):
        from src.pcpi import saas_session_manager

        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.text = json.dumps(
            [
                {
                    "_id": "container1",
                    "network": {
                        "ports": [
                            {"container": 80, "host": 8080, "hostIP": "127.0.0.1"}
                        ]
                    },
                },
                {
                    "_id": "container2",
                    "networkSettings": {
                        "ports": [
                            {
                                "containerPort": 443,
                                "hostPort": 8443,
                                "hostIP": "127.0.0.1",
                            }
                        ]
                    },
                },
            ]
        )
        mock_get.return_value = mock_response

        session = saas_session_manager.SaaSCWPSession(
            tenant_name="test_tenant",
            a_key="test_a_key",
            s_key="test_s_key",
            api_url="https://test.api.url",
            verify=False,
            proxies={},
            logger=py_logger,
        )

        open_ports = session.get_open_container_ports()

        expected_ports = [
            json.dumps(
                {
                    "id": "container1",
                    "open_ports": [
                        {
                            "port": 80,
                            "host_port": 8080,
                            "host_ip": "127.0.0.1",
                            "nat": None,
                            "type": "network",
                        }
                    ],
                    "network": {
                        "ports": [
                            {"container": 80, "host": 8080, "hostIP": "127.0.0.1"}
                        ]
                    },
                    "networks": {},
                },
                indent=2,
            ),
            json.dumps(
                {
                    "id": "container2",
                    "open_ports": [
                        {
                            "port": 443,
                            "host_port": 8443,
                            "host_ip": "127.0.0.1",
                            "type": "networkSettings",
                        }
                    ],
                    "network": {},
                    "networks": {
                        "ports": [
                            {
                                "containerPort": 443,
                                "hostPort": 8443,
                                "hostIP": "127.0.0.1",
                            }
                        ]
                    },
                },
                indent=2,
            ),
        ]

        self.assertEqual(open_ports, expected_ports)


if __name__ == "__main__":
    unittest.main()
