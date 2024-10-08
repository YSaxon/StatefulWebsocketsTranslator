# StatefulWebsocketsTranslator

StatefulWebsocketsTranslator is a MITM (Man-in-the-Middle) proxy tool designed to convert WebSocket messages to HTTP requests and back, to allow web app vuln scanners that don't work (well) with websocket messages to scan websocket targets as if they were regular webservers.




## Overview
![architectural diagram](https://github.com/user-attachments/assets/bcb85bef-016b-4dad-8f53-1df19248cde6)

* First examine the ws messages and configure the keys for state and action. See below.

* Set this script as an upstream proxy for your regular attack proxy (eg Burp). 

* Set Burp as your browser's proxy and browse the target site as usual. Any non-ws messages will be forwarded unchanged.

* Any websocket messages will be translated to HTTP and forwarded backwards through Burp in order to populate the target map.

* You will see a site appear in the target map called `{targetsite.com}.wsmockserver` with those translated HTTP messages.

* Tell Burp to scan that site. All the web requests it makes to `{targetsite.com}.wsmockserver` will be translated into ws messages.

## Installation

   ```
   git clone https://github.com/ysaxon/StatefulWebsocketsTranslator.git
   cd StatefulWebsocketsTranslator
   pip install mitmproxy httpx
   ```

## Usage

1. Start Burp Suite and configure it to listen on the default port (8080).

2. Configure Burp Suite to use an upstream proxy:
   - Go to Settings -> Network -> Connections -> Upstream Proxy Servers
   - Add a rule to forward all traffic (*) to `127.0.0.1:8081`

3. Run the StatefulWebsocketsTranslator:
   ```
   python wstranslator.py
   ```

   You can customize the configuration using command-line arguments:
   ```
   python wstranslator.py --burp 8080 --mitm 8081 --loglevel INFO --id_request id --action action --id_response requestId
   ```

4. The script will start and perform a self-test to ensure everything is set up correctly.

5. Configure your browser to connect through the Burp Suite proxy (default: `127.0.0.1:8080`).

6. Start using your WebSocket application. The tool will automatically translate WebSocket messages to HTTP requests that can be intercepted and analyzed by Burp Suite.

## Configuration Options

- `--burp`: Port that Burp proxy is listening on (default: 8080)
- `--mitm`: Port for the MITM proxy (default: 8081)
- `--loglevel`: Set the logging level (choices: DEBUG, INFO, WARNING, ERROR, CRITICAL; default: INFO)

These should all be fairly clear.
  
- `--id_request`: State ID key in the client's WebSocket messages (default: 'id')
- `--id_response`: State ID key in the server's WebSocket messages (default: 'requestId')

These are keys for the request and response respectively, that together define which response is to which request. Without this it would be hard or impossible to run a vuln scan in parallel, at least while using standard web scanner paradigms as this is meant to allow. In order to prevent duplicate state tokens while using the webscanner, the script will always create a new guid for the websocket messages to/and from the server itself, and then restore the old state token used when responding back to the browser or scanner.

- `--action`: Action key in the client's WebSocket messages (default: 'action')
  
A key defining the action or route for the message, which will be used as the URL path in the HTTP conversion


## Limitations

- The tool as coded assumes your websocket messages as serialized as JSON, however the serialization is centralized at the top, so modifying it should be easy.
- Similiarly the tool assumes your statetokens are GUIDs but can be easily modified to use an integer counter or some other such state token instead. 

- If your websocket messages do not contain state tokens, there's really nothing I can do for you, as this entire architecture requires state tokens on a deep level.

- Right now, the script has no ability to initialize the websocket creation, so each time you start, you will need initiate the connection by either bring up the site in your browser, or having Burp reconnect - if you highlight a websocket message in the history tab and send it to repeater, it will give you an option to reconnect if you aren't connected. This is probably something I should add, but haven't yet. Pull requests welcome.



## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
