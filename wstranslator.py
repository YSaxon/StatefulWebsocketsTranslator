import argparse
import asyncio
import uuid
import logging
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import http, ctx
from mitmproxy.http import HTTPFlow, Response
from mitmproxy.websocket import WebSocketMessage
import httpx
from urllib.parse import quote, unquote
import json

DEFAULT_BURP_PORT = 8080
DEFAULT_MITM_PORT = 8081
DEFAULT_ID_REQUEST = 'id'
DEFAULT_ACTION = 'action'
DEFAULT_ID_RESPONSE = 'requestId'
DEFAULT_LOG_LEVEL = 'INFO'

MOCKSERVER_HOST_SUFFIX = ".wsmockserver"

LOGGER = logging.getLogger(__name__)

def setup_logger():
    LOGGER.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)

setup_logger()

def url_safe_encode(s: str) -> str:
    return quote(s, safe=':')

def url_safe_decode(s: str) -> str:
    return unquote(s)

class SocketHttpTranslator:
    def __init__(self, guid_key_send, guid_key_receive, action_key, burp_proxy_port):
        self.guid_key_send = guid_key_send
        self.guid_key_receive = guid_key_receive
        self.action_key = action_key
        self.flows = {}  # Dictionary to store flows for each host
        self.burp_proxy_port = burp_proxy_port
        self.new_guid_to_server_ws_futures = {}
        self.httpx_client = httpx.AsyncClient(proxy=f"http://localhost:{self.burp_proxy_port}", verify=False)

    # mitmproxy hooks

    async def websocket_start(self, flow: HTTPFlow):
        host = flow.request.host
        LOGGER.info(f"WebSocket connection established for host {host}: {flow.request.url}")
        self.flows[host] = flow

    async def websocket_message(self, flow: HTTPFlow):
        if not self._validate_websocket_flow(flow):
            return

        message = flow.websocket.messages[-1]
        host = flow.request.host
        if message.from_client:
            await self._handle_client_websocket(flow, message, host)
        else:
            await self._handle_server_websocket(flow, message, host)

    async def request(self, flow: HTTPFlow):
        LOGGER.info(f"Request: {flow.request.method} {flow.request.url}")
        if flow.request.host.endswith(MOCKSERVER_HOST_SUFFIX):
            return await self._handle_mock_server_request(flow)

    async def response(self, flow: HTTPFlow):
        LOGGER.info(f"Response: {flow.response.status_code} {flow.request.url}")
        if flow.request.host.endswith(MOCKSERVER_HOST_SUFFIX):
            LOGGER.info(f"Response from webserver: {flow.response.text}")
            return await self._handle_mock_server_response(flow)

    # helpers

    def _validate_websocket_flow(self, flow: HTTPFlow) -> bool:
        if flow.websocket is None:
            LOGGER.warning(f"No websocket on websocket_message {flow}")
            return False
        if not flow.websocket.messages:
            LOGGER.warning(f"No messages on websocket_message {flow}")
            return False
        return True

    async def _handle_client_websocket(self, flow: HTTPFlow, message: WebSocketMessage, host: str):
        LOGGER.info(f"Translating client WebSocket to web request for host {host}: {message}")
        message_json = self._parse_json_message(message)
        if not message_json:
            return

        action = message_json.get(self.action_key)
        guid = message_json.get(self.guid_key_send)

        if not guid or guid == "heartbeatAck" or guid in self.new_guid_to_server_ws_futures:
            LOGGER.info(f"Skipping message with GUID: {guid}")
            return

        message.drop()  # Don't forward to server as is
        await self._send_web_request_through_proxy(action, message_json, host)

    async def _handle_server_websocket(self, flow: HTTPFlow, message: WebSocketMessage, host: str):
        message_json = self._parse_json_message(message)
        if not message_json:
            return

        guid = message_json.get(self.guid_key_receive)
        if not guid or guid == "heartbeatAck":
            return

        if guid not in self.new_guid_to_server_ws_futures:  # Not a response to a client message
            return

        message.drop()  # Don't forward to client as is
        future = self.new_guid_to_server_ws_futures.pop(guid)
        future.set_result(message_json)

    async def _handle_mock_server_request(self, flow: HTTPFlow):
        action = url_safe_decode(flow.request.path_components[0])
        guid = flow.request.headers.get("guid")
        # host = flow.request.headers.get("wshost")
        host = flow.request.host.split(MOCKSERVER_HOST_SUFFIX)[0]
        try:
            data = json.loads(flow.request.get_text())
        except json.JSONDecodeError as e:
            LOGGER.debug(f"mitmproxy translator: Failed to parse JSON from mock server request: {flow.request.get_text()}")
            flow.response = Response.make(400, json.dumps({"error": "Cannot parse JSON. (likely just an overzealous vuln scanner sending malformed data)"}), {"Content-Type": "application/json"})
            flow.resume()
            return
        LOGGER.info(f"Mock server request for action '{action}' to host '{host}': {data}")

        old_guid = guid
        new_guid = str(uuid.uuid4())
        data[self.guid_key_send] = new_guid
        data[self.action_key] = action

        server_ws_response = asyncio.Future()
        self.new_guid_to_server_ws_futures[new_guid] = server_ws_response

        flow.intercept()

        if host not in self.flows:
            LOGGER.error(f"No WebSocket connection exists for host: {host}")
            flow.response = Response.make(500, json.dumps({"error": f"No WebSocket connection for host: {host}"}), {"Content-Type": "application/json"})
            flow.resume()
            return

        await self._send_websocket_to_server(data, host)

        try:
            response = await asyncio.wait_for(server_ws_response, timeout=5)
            del response[self.guid_key_receive]
            flow.resume()
            flow.response = Response.make(200, json.dumps(response), {"Content-Type": "application/json", "guid": old_guid})
        except asyncio.TimeoutError:
            del self.new_guid_to_server_ws_futures[new_guid]
            flow.response = Response.make(504, json.dumps({"error": "Request timed out"}), {"Content-Type": "application/json"})
        finally:
            self.new_guid_to_server_ws_futures.pop(new_guid, None)

    async def _handle_mock_server_response(self, flow: HTTPFlow):
        guid = flow.request.headers.get("guid")
        # host = flow.request.headers.get("wshost")
        host = flow.request.host.split(MOCKSERVER_HOST_SUFFIX)[0]
        response = json.loads(flow.response.get_text())
        response[self.guid_key_receive] = guid
        await self._send_websocket_to_client(json.dumps(response), host)

    async def _send_web_request_through_proxy(self, action, data, host):
        action = url_safe_encode(action)
        guid = data[self.guid_key_send]

        if isinstance(data, str):
            data = json.loads(data)
        del data[self.action_key]
        del data[self.guid_key_send]

        data = json.dumps(data)

        url = f"http://{host}{MOCKSERVER_HOST_SUFFIX}/{action}"
        headers = {"Content-Type": "application/json", "guid": guid, "wshost": host}
        LOGGER.info(f"Sending request to {url} for host {host}: {data}")

        try:
            await self.httpx_client.post(url, headers=headers, data=data, timeout=.05)
        except:
            pass  # for whatever reason, this request blocks the event loop until it times out. But for our purposes it's good enough to send it and forget it

    async def _send_websocket_to_client(self, msg, host):
        await self._send_websocket(msg, True, host)

    async def _send_websocket_to_server(self, msg, host):
        await self._send_websocket(msg, False, host)

    async def _send_websocket(self, msg, to_client: bool, host: str):
        await self._check_or_refresh_flow(host)
        if isinstance(msg, dict):
            msg = json.dumps(msg)
        if isinstance(msg, str):
            msg = msg.encode()
        LOGGER.info(f"Sending WebSocket to {'client' if to_client else 'server'} for host {host}: {msg}")
        ctx.master.commands.call("inject.websocket", self.flows[host], to_client, msg)
        await asyncio.sleep(1)

    async def _check_or_refresh_flow(self, host):
        if host not in self.flows:
            LOGGER.error(f"No flow set for host {host}. Refresh flow not implemented yet")
            return
        if self.flows[host].websocket is None:
            LOGGER.warning(f"No websocket on flow for host {host}")
            return

    def _parse_json_message(self, message: WebSocketMessage):
        if not message.is_text:
            LOGGER.warning(f"Message is not text: {message}")
            return None
        try:
            return json.loads(message.text)
        except json.JSONDecodeError:
            LOGGER.warning(f"Failed to parse WebSocket message as JSON: {message.text}")
            return None

# Main setup

config = argparse.Namespace()
config.burp = DEFAULT_BURP_PORT
config.mitm = DEFAULT_MITM_PORT
config.id_request = DEFAULT_ID_REQUEST
config.action = DEFAULT_ACTION
config.id_response = DEFAULT_ID_RESPONSE
config.loglevel = DEFAULT_LOG_LEVEL

class ProxyTester:
    def __init__(self, burp_proxy_port, mitmproxy_port):
        self.burp_proxy_port = burp_proxy_port
        self.mitmproxy_port = mitmproxy_port

    async def running(self):
        await self.test_proxy_setup()

    async def request(self, flow: HTTPFlow):
        if flow.request.host == "proxytestping":
            flow.response = Response.make(200, "Pong", {"Content-Type": "text/plain"})

    async def test_proxy_setup(self):
        LOGGER.info("Testing proxy setup")
        async with httpx.AsyncClient(proxy=f"http://localhost:{self.burp_proxy_port}") as client:
            # Send a request to example.com with burpproxy only
            try:
                response = await client.get("http://example.com",timeout=10)
                if not response.status_code == 200:
                    raise Exception(f"Failed to connect to example.com via proxy: {response.status_code}")
                LOGGER.info(f"BURP PROXY WORKING: Connected to example.com via burp proxy at port {self.burp_proxy_port}")
            except Exception as e:
                LOGGER.error(f"Failed to connect to example.com via burp proxy at port {self.burp_proxy_port}: {e}\n\nIs burp proxy running on {self.burp_proxy_port}?\nIs your intercept on and blocking the ping?")
                return False

        async with httpx.AsyncClient(proxy=f"http://localhost:{self.mitmproxy_port}") as client:
            #send a request to ping to test self proxy listening
            try:
                response = await client.get("http://proxytestping",timeout=10)
                if not response.status_code == 200 or not response.text == "Pong":
                    raise Exception(f"Failed to connect to ping: {response.status_code} {response.text}")
                LOGGER.info(f"OWN PROXY WORKING: Connected to ping at port {self.mitmproxy_port}")
            except Exception as e:
                LOGGER.error(f"Failed to connect to mitmproxy at port {self.mitmproxy_port}: {e}\nMitmproxy appears to have failed to listen?")
                return False

        async with httpx.AsyncClient(proxy=f"http://localhost:{self.burp_proxy_port}") as client:
            #send a request to pingserver via burp proxy to test burps upstream proxy settings
            try:
                response = await client.get("http://proxytestping",timeout=10)
                if not response.status_code == 200 or not response.text == "Pong":
                    raise Exception(f"Failed to connect to ping via burp proxy: {response.status_code} {response.text}")
                LOGGER.info(f"UPSTREAM PROXY WORKING: Connected to ping via burp proxy at port {self.burp_proxy_port}")
            except Exception as e:
                LOGGER.error(f"Failed to connect to upstream mitmproxy via burp proxy at port {self.burp_proxy_port}: {e}\n\nIs burp proxy set to proxy traffic upstream to port {self.mitmproxy_port}?\nGo to Settings->Network->Connections->Upstream Proxy Servers and set the proxy for * to localhost:{self.mitmproxy_port}")
                return False

            LOGGER.info("All tests passed")
            return True


async def run_mitm_proxy(args=config):
    combined_server = SocketHttpTranslator(guid_key_receive=config.id_response, guid_key_send=config.id_request, action_key=config.action, burp_proxy_port=config.burp)
    proxy_tester = ProxyTester(burp_proxy_port=config.burp, mitmproxy_port=config.mitm)
    addons = [combined_server,proxy_tester]

    opts = options.Options(listen_host='127.0.0.1', listen_port=config.mitm)
    m = DumpMaster(opts)
    m.addons.add(*addons)
    try:
        await m.run()
    except KeyboardInterrupt:
        m.shutdown()

async def main(args):
    await run_mitm_proxy(args)

def parse_arguments():
    parser = argparse.ArgumentParser(description='StatefulWebsocketsTranslator: a MITM proxy to convert WebSocket messages to HTTP requests and back')
    parser.add_argument('--burp', type=int, default=DEFAULT_BURP_PORT, help='Port that Burp proxy is listening on')
    parser.add_argument('--mitm', type=int, default=DEFAULT_MITM_PORT, help='Port for the MITM proxy (Burp must be set to forward traffic upstream to this port)')
    parser.add_argument('--loglevel', default=DEFAULT_LOG_LEVEL, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')
    parser.add_argument('--id_request', help='State ID key in the client\'s websocket messages', default=DEFAULT_ID_REQUEST)
    parser.add_argument('--action', help='Action key in the client\'s websocket messages', default=DEFAULT_ACTION)
    parser.add_argument('--id_response', help='State ID key in the server\'s websocket messages', default=DEFAULT_ID_RESPONSE)
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    asyncio.run(main(args))
