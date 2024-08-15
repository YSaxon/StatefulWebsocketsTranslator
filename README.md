# StatefulWebsocketsTranslator

StatefulWebsocketsTranslator is a MITM (Man-in-the-Middle) proxy tool designed to convert WebSocket messages to HTTP requests and back. This tool is particularly useful for testing and analyzing WebSocket-based applications using HTTP-based security tools like Burp Suite.

## Features

- Provides a mock webserver to which HTTP requests can be made, that will be translated into websocket messages, and back
- Forwards actual websocket messages triggered by normal usage to your primary attack proxy (Burp, ZAP, etc), in order to populate the target map

## Prerequisites

- Python 3.7+
- mitmproxy
- httpx

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/ysaxon/StatefulWebsocketsTranslator.git
   cd StatefulWebsocketsTranslator
   ```

2. Install the required dependencies:
   ```
   pip install mitmproxy httpx
   ```

## Usage

1. Start Burp Suite and configure it to listen on the default port (8080).

2. Configure Burp Suite to use an upstream proxy:
   - Go to Settings -> Network -> Connections -> Upstream Proxy Servers
   - Add a rule to forward all traffic (*) to `127.0.0.1:8081`

3. Run the StatefulWebsocketsTranslator:
   ```
   python stateful_websockets_translator.py
   ```

   You can customize the configuration using command-line arguments:
   ```
   python stateful_websockets_translator.py --burp 8080 --mitm 8081 --loglevel INFO --id_request id --action action --id_response requestId
   ```

4. The proxy will start and perform a self-test to ensure everything is set up correctly.

5. Configure your WebSocket client to connect through the Burp Suite proxy (default: `127.0.0.1:8080`).

6. Start using your WebSocket application. The tool will automatically translate WebSocket messages to HTTP requests that can be intercepted and analyzed by Burp Suite.

## Configuration Options

- `--burp`: Port that Burp proxy is listening on (default: 8080)
- `--mitm`: Port for the MITM proxy (default: 8081)
- `--loglevel`: Set the logging level (choices: DEBUG, INFO, WARNING, ERROR, CRITICAL; default: INFO)
- `--id_request`: State ID key in the client's WebSocket messages (default: 'id')
- `--action`: Action key in the client's WebSocket messages (default: 'action')
- `--id_response`: State ID key in the server's WebSocket messages (default: 'requestId')

## How It Works

1. WebSocket messages from the client are intercepted and converted to HTTP POST requests.
2. These HTTP requests are sent through Burp Suite for analysis and modification.
3. The proxy intercepts the responses and converts them back to WebSocket messages.
4. The converted messages are sent to the original WebSocket server.
5. Responses from the WebSocket server are similarly intercepted, converted, and passed through Burp Suite before being sent back to the client.

## Limitations

- This tool assumes a specific structure for WebSocket messages. You may need to modify the code to match your application's message format.
- Performance may be impacted due to the conversion process and additional network hops.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and testing purposes only. Always ensure you have permission before testing any systems you do not own or have explicit authorization to test.