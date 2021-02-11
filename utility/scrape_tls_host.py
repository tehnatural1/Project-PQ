"""
This script goes through the IP address of remote devices known to have used
'week keys' during the generation of a certificate.

It connects to the remote peer, scrapes any data presented, and attempts to
identify the model of the device that is hosting the web page.

"""

import asyncio
import ssl
import pprint


# Known D-Link prefix to all their devices
DLINK_MODEL_PREFIX  =   ["dcs-", "dir-"]

# Known Netgear div container for the string identifying the model
NETGEAR_MODEL_DIV   =   '<div class="forbgsh1">'

# Known Vigor Router identifier for the model
VIGOR_MODEL_VAR     =   "product_name"

# Maximum number of IPv4 addresses allowed to be checked in parallel
MAX_GROUP_SIZE      =   256

# Default encoding to use when communicating with a peer
ENCODING            =   "utf-8"

# Maximum amount of time to wait for a peer handshake to complete
TIMEOUT             =   10

# Whether or not to record the body of the HTML document
CAPTURE_HTML_BODY   =   True

# Globals used to store information on the remote devices
devices             =   {}
timeouts            =   set()
failures            =   {}
idks                =   {}
unreachable         =   set()


async def send_headers(writer: asyncio.StreamWriter=None,
                       reader: asyncio.StreamReader=None,
                       location: str="",
                       ipv4_address: str="") -> list:
    """
    Sends the standard headers to the peer which, among other things, attempts
    to bypass the router authorization request prompt.

    Args:
        writer (asyncio.StreamWriter): Stream to write headers to.
        reader (asyncio.StreamReader): Stream to read headers from.
        location (str): URL request path on the peer.
        ipv4_address (str): IPv4 address of the peer.

    Returns:
        (list): Containing the data read from the peer.

    """
    # Attempt to get the device to respond with its device name
    writer.write(
        b'\r\n'.join(
            [
                'GET /{} HTTP/1.0'.format(location).encode(ENCODING),
                'Authorization: Basic admin:admin'.encode(ENCODING),
                'Host: {}'.format(ipv4_address).encode(ENCODING),
                'Content-Type: text/html; charset={}'.format(ENCODING).encode(ENCODING),
                b'Connection: close',
                b'', b''
            ]
        )
    )

    # Container for the peer's headers
    headers = []

    # Get the headers for the response
    async for raw_data in reader:
        header = raw_data.decode(ENCODING).strip()
        if not header.strip(): break
        headers.append(header)

    return headers


async def get_body(reader: asyncio.StreamReader=None,
                   headers: list=[]) -> list:
    """
    Attempts to collect the content of the document body presented by the peer.

    Args:
        reader (asyncio.StreamReader): Stream to read the document body from.
        headers (list): The list of headers collected from the peer, used to
            identify the encoding used by the peer.

    Returns:
        (list): Containing the data read from the peer.

    """
    # Container for the peer's document body
    body = []

    # Get the body of the response
    if (CAPTURE_HTML_BODY):

        # Identify the encoding used by the client
        encoding = get_encoding(headers)

        # Read the data from the stream
        async for raw_data in reader:
            body.append( raw_data.decode(encoding).strip() )

    return body


def get_data(headers:list=[], item:str="", idx:int=1)->str:
    """
    Attempts to extract data from the headers at the specified index location.

    Args:
        headers (str list): The headers sent by the peer.
        item (str): The data identifier of the header.
        idx (int): The location of the data.

    Returns:
        (None): If the data was not found at the specified location.
        (str): The data at the indexed location specified by the item.

    """
    # Iterate through the headers
    for header in headers:

        # Check for the identifier in the data
        if (item.lower() in header.lower()):
            parts = header.split()

            # Ensure a valid index
            if (len(parts) > idx): return parts[idx]

    return item


def get_device_dlink(headers):
    """
    Attempt to identfy the model of the device from the data contained in the
    headers provided from the peer.

    NOTE: D-Link devices only.

    Args:
        headers (str list): The headers sent by the peer.

    Returns:
        (None): If no model was found in the headers.
        (str): Containing the model of the device

    """
    # Iterate through the headers
    for header in headers:
        header = header.lower()

        # Check the header for information on the device model
        if (("server" in header) or
            (
                ("authenticate" in header) and
                ("realm"        in header)
            )
        ):
            # Iterate over the data in the header
            for part in header.split():

                # Check for known model identifying prefixes
                if (any(e in part for e in DLINK_MODEL_PREFIX)):
                    return part.replace('"', "").replace("realm=", "").upper()

    return None


def get_device_netgear(body):
    """
    Attempt to identfy the model of the device from a data identification <div>
    present on some netgear devices.

    NOTE: NetGear devices only.

    Args:
        headers (str list): The headers sent by the peer.

    Returns:
        (None): If no model was found in the headers.
        (str): Containing the model of the device

    """
    # Iterate over the data contained in the page body
    for i in range(len(body)):
        line = body[i].lower()

        # Check for identification div used to extract the device's model
        if (NETGEAR_MODEL_DIV in line):
            return line[len(NETGEAR_MODEL_DIV):line.find("</div>")]

    return None


def get_device_vigor(body):
    """
    Attempt to identfy the model of the device from a data identification field
    placed in a <div> on some vigor devices.

    NOTE: Vigor devices only.

    Args:
        headers (str list): The headers sent by the peer.

    Returns:
        (None): If no model was found in the headers.
        (str): Containing the model of the device

    """
    # Join the data of the body since the id location must be sliced
    body    =   ''.join(body)
    p_idx   =   body.find(VIGOR_MODEL_VAR)

    # Ensure the variable used to identify the model was found
    if (p_idx > 0):

        # Start from the model variable and find the end of the div
        start = body.find(">", p_idx) + 1
        return body[start:body.find("<", start)]

    return None


def get_encoding(headers):
    """
    Extract the encoding used by the peer from the provided headers.

    Args:
        headers (str list): The headers sent by the peer.

    Returns:
        (str): Containing the encoding specified in the header, or the default
            encoding if a header identifying the encoding is not found.

    """
    # Iterate through the headers
    for header in headers:
        header = header.strip().lower()

        # Check the header for information on the encoding
        if (header.startswith('content-type')):

            # Iterate over the data in the header
            for entry in header.split(';'):

                # Check for encoding identifier string
                if (entry.strip().startswith('charset')):
                    parts = entry.split('=')

                    # Ensure proper formatting of the (identifier=value) data
                    if (len(parts) > 1): return parts[1].strip()

    # Did not find a specified encoding type
    return ENCODING


async def ssl_future(ipv4_address: str="",
                     port: int=443,
                     sslctx: ssl.SSLContext=None,
                     location: str="",
                     redirects: int=0) -> None:
    """
    Attempts to connect to a remote network device and obtain any header or data
    presented during the connection.

    The data given by the peer is checked for a device model and if found the
    the data is is sorted into groups and stored into the global variables.

    Reference:
        Asyncrhonous stream communication with network connections.
        https://docs.python.org/3/library/asyncio-stream.html

    Args:
        ipv4_address (str): IPv4 address used to attempt a connection.
        port (int): Port to attempt communication to the device on.
        sslctx (ssl.SSLContext): SSL Context defining which protocol to use.
        location (str): URL location that is appended to address.
        redirects (int): Amount of times a peer has redirected the location.

    """
    global failures, timeouts, devices, idks, unreachable
    try:
        # Read and Write streams from the open socket
        r, writer   =   await asyncio.wait_for(
                                asyncio.open_connection(
                                        ipv4_address,
                                        port,
                                        ssl = sslctx
                                ),
                                timeout = TIMEOUT
                        )

        # Attempt to get the device to respond with its device name
        headers     =   await send_headers(writer, r, location, ipv4_address)
        body        =   await get_body(r, headers)

        # Device model not found in header, try again in the body
        if (location == "weblogin.htm"):
            device = get_device_vigor(body)
        elif (location == "scgi-bin/platform.cgi"):
            device = get_device_netgear(body)
        else:
            device = get_device_dlink(headers)

        # Extract remaining data from the headers
        status      =   get_data(headers, "HTTP/")
        location    =   get_data(headers, "location")

        # Gracefully close the connection to the client
        writer.close()

        # Follup up to three redirects as long as a locaiton was provided
        if (("303" in status) and (location != None) and (redirects < 3)):
            return await ssl_future(
                                        ipv4_address    =   ipv4_address,
                                        port            =   port,
                                        sslctx          =   sslctx,
                                        location        =   location,
                                        redirects       =   (redirects + 1)
            )

        # Create a container for the collected data
        device_data = {"HEADERS": headers, "BODY": body, "DEVICE": device}

        # Update the device dictionaries with the information from the device
        if (device != None): devices[ipv4_address] = device_data
        else:                idks[ipv4_address]    = device_data

    except asyncio.TimeoutError:
        timeouts.add(ipv4_address)

    except Exception as e:
        if ("Connect call failed" in str(e)):
            unreachable.add(ipv4_address)
        else:
            failures[ipv4_address] = str(e)


def collect_device_data(ipv4_addresses, location=""):
    """
    Attempts to connect to remote network device and collect the data presented
    by the peer to identify a model for the device hosting the web page.

    Args:
        ipv4_addresses (list): A list of ipv4 addresses to be scraped.

    """
    # Stored futures, Context and event loop
    sslctx  =   ssl.SSLContext(ssl.PROTOCOL_TLS)
    loop    =   asyncio.get_event_loop()
    idx     =   0
    tasks   =   []

    # Check IPv4 addresses in a parallel group
    while(idx < len(ipv4_addresses)):
        tasks.append( ssl_future(ipv4_addresses[idx], 443, sslctx, location) )
        idx += 1

        # Ensure max group size is met and the index has not exceed the array
        if ((idx % MAX_GROUP_SIZE == 0) or (idx >= len(ipv4_addresses))):
            print("Checking IP Group, current idx:", idx)

            # Wrap the tasks to schedule execution, execute them and reset tasks
            future = asyncio.ensure_future( asyncio.gather(*tasks) )
            loop.run_until_complete(future)
            tasks = []


def get_ips_from_file(file_path: str="") -> list:
    """
    Reads a list of IPs from a file location.

    Args:
        file_path (str): File location of IPv4 list.

    """
    ipv4_addresses = []

    for line in open(file_path, "r").readlines():
        ipv4_addresses.append(line.strip())

    return ipv4_addresses


if (__name__ == "__main__"):

    collect_device_data( get_ips_from_file("./SCRAPE_IPS") )

    print("\nTIMEOUTS:\n", timeouts)
    print("\nUNREACHABLES:\n", unreachable)
    print("\nFAILURES:")
    pprint.pprint(failures)

    print("\nDEVICE MODELS:")
    pprint.pprint(devices, width=240)

    print("\nUNKNOWN MODELS:")
    pprint.pprint(idks, width=240)

