"""
This script will collect any public key presented by a peer connection during
a SSL or SSH handshake and store the resulting key for entropy analysis.


IMPORTANT NOTE:
    Although great lengths have been taken to avoid triggerring detection scans
    from ISP's, Web Servercies, and remote hosts, there is no garuntee this
    script will avoid detection (Though it has been shown to scan the entire
    ipv4 address space without detection during the month of October, 2020).

    Furthermore, the scanning of port 22 (SSH), in most cases, is considered a
    security vulnerability scan and can result in the IP address of the machine
    running this script to be blocked -- indefinitely. For this reason, the
    scanning of port 22 is disabled by default. Scan this port at your own risk.


Module Overview:
    1.  The main process will create two thread-safe queues and a process pool.

        1.1.    The processes of the pool will continually do an execute
                blocking read from the queue, which will contain an IPv4 address
                with the last 8 bits unset.

        1.2.    Upon reading an IPv4 address, the processes of the pool will
                generate 256 asynchronous tasks each assigned with a seperate
                IPv4 address with the last 8 bits set from 0-255 and either the
                SSL port (443) or SSH port (22).

        1.3.    Each of the process' asynchronous tasks will attempt to connect
                to it's assigned IPv4 address and record any certificate
                presented from the remote network device during the handshake
                into a thread-safe queue.

    2.  The main process will begin the generation of IPv4 addresses without
        the last 8 bits set and placing them into an array. The resulting array
        is randomly shuffled and each item is then placed into the thread-safe
        queue for the process pool to consume.

    3.  The main process will begin consuming and recording the data the process
        pool generates until not only the generated addresses are consumed but
        also the output of the thread pool is consumed.

    4.  The main process will then clean up the process pool and terminate the
        program.


Estimated Performance and Duration Calculations:

    [IPv4_COUNT]: Amount of IPv4 being Scanned
        >>> 256**3 * (IPV4_ADDR_END - IPV4_ADDR_START)

    [SCAN_RATE]: Current IPv4 Scan rate (IPs being checked a second)
        >>> 256 * (PROCESS_POOL_SIZE / PEER_CONNECTION_TIMEOUT)

    [ETA]: Amount of time (in hours) to complete the scan.
        >>> [IPv4_COUNT] / [SCAN_RATE] / 60s / 60min

    Example: To scan all IPv4 addresses in the range 20.0.0.0 -> 30.0.0.0 with
    a process pool size of 15, a connection timeout of two seconds, and ignoring
    port 22 (DEFAULT SETTINGS).
        >>> ETA (hours) = [IPv4_COUNT] / [SCAN_RATE] / 60 seconds / 60 minutes
        >>> ETA (hours) = [256**3 * (30 - 20)] / [256 * (15 / 2)] / 60s / 60m
        >>> ETA (hours) = 24.2726 Hours

"""

# Asynchronous execution, connections, tasks and futures
import asyncio
import ssl
import asyncssh

# Parallel execution and process coordination
import multiprocessing

# Peer certificate conversion
import base64

# Shuffling array of addresses to ensure DNS servers are not queuried repeatedly
import random

# Ensuring that reserved address space is not checked
from ipaddress                  import ip_address, ip_network

# Package Imports - Logging, Certificate Collection
from utility.util               import log, clog


# Amount of time to be block the main thread while waiting for the process pool
# to collect certificates. After the blocking read the main process will check
# the ipv4 address queue and if it has been consumed, it will begin cleanup.
CERT_QUEUE_READ_TIMEOUT         =   20

# Amount of a time alotted for a peer connection to be created and the amount
# of time a peer has to send to respond with its certificate.
PEER_CONNECTION_TIMEOUT         =   1

# Sets the amount of forked processes that will be created. Each forked process
# runs 256 asynchronous tasks on a IP group. Not only the quality of the systems
# internet but also the amount of system memory available should be considered
# when adjusting this value.
PROCESS_POOL_SIZE               =   15

# Sets the initial IP address group start point. For instance a value of 14 will
# start the scanning of ip address from 14.0.0.0 -> {IPV4_END}.255.255.255
IPV4_ADDR_START                 =   120

# Sets the final IP address group end point. For instance a value of 14 will
# start the scanning of ip address from {IPV4_START}.0.0.0 -> 14.255.255.255
IPV4_ADDR_END                   =   130

# Sets the handshake port number for SSL
SSL_PORT                        =   443

# Enable / Disable the SSL port scan
SCAN_SSL_PORT                   =   True

# Sets the handshake port number for SSH
SSH_PORT                        =   22

# Enable / Disable the SSH port scan
SCAN_SSH_PORT                   =   False


def store_certificates(
        responses: list=[],
        certificates: multiprocessing.Queue=None
    ) -> None:
    """
    Filter all peer responses and store the collected certificates in a
    thread-safe queue for the main process to consume and store.

    Args:
        responses (list): Contains each response recorded from a peer. The
            responses should be as follows [(ip, cert), (ip, cert), None, ...]
        certificates (multiprocessing.Queue): Thread-safe queue to store any
            collected certificate during the handshake with the peer.

    """
    # Filter any 'None' entry from the response list
    certs = list(filter(None, responses))

    # Ensure there was at least one certificate in the response list
    if (len(certs) == 0): return

    # Store certificate information as json compatible
    certificates.put('"{}",'.format('",\n"'.join('":"'.join(i) for i in certs)))


async def ssh_future(
        ipv4_address: str="",
        port: int=22
    ) -> tuple:
    """
    Attempts to connect to a remote network device and obtain the host key
    presented by the peer during the SSH handshake.

    Args:
        ipv4_address (str): IPv4 address used to attempt a connection.
        port (int): Port to attempt communication to the device on.

    Returns:
        (None): If the connection fails, or any exception is generated.
        (Tuple): Containing the IP address connected to and the collected cert.

    """
    try:
        # Wait for the key to be collected during the handshake
        response    =   await asyncio.wait_for(
                                asyncssh.get_server_host_key(
                                        ipv4_address,
                                        port
                                ),
                                timeout = PEER_CONNECTION_TIMEOUT
                        )

        # Record the public key presented during the handshake
        public_key  =   base64.b64encode(
                                response.encode_ssh_public()
                        ).decode()

        # Create an immutable tuple for the ip group task to store
        return ("{}:{}".format(ipv4_address, port), public_key)

    except asyncio.TimeoutError:
        log.error("{:<15} time out".format(ipv4_address))

    except Exception as e:
        log.error("{:<15} {}".format(ipv4_address, e))


async def ssl_future(
        ipv4_address: str="",
        port: int=443,
        sslctx: ssl.SSLContext=None
    ) -> tuple:
    """
    Attempts to connect to a remote network device and obtain any certificate
    presented by the peer during the SSL handshake.

    Args:
        ipv4_address (str): IPv4 address used to attempt a connection.
        port (int): Port to attempt communication to the device on.
        sslctx (ssl.SSLContext): SSL Context defining which protocol to use.

    Returns:
        (None): If the connection fails, or any exception is generated.
        (Tuple): Containing the peer's IPv4 address and the certificate
            presented during the SSL handshake.

    """
    try:
        # Read and Write streams from the open socket
        _, writer   =   await asyncio.wait_for(
                                asyncio.open_connection(
                                        ipv4_address,
                                        port,
                                        ssl = sslctx
                                ),
                                timeout = PEER_CONNECTION_TIMEOUT
                        )

        # Close the stream writer and gracefully disconnect from the client
        writer.close()

        # Record the certificate presented during the SSL handshake
        peer_cert   =   base64.b64encode(
                                writer._transport
                                    ._ssl_protocol
                                    ._extra['ssl_object']
                                    .getpeercert(True)
                        ).decode()

        # Create an immutable tuple for the ip group task to store
        return ("{}:{}".format(ipv4_address, port), peer_cert)

    except asyncio.TimeoutError:
        log.error("{:<15} time out".format(ipv4_address))

    except Exception as e:
        log.error("{:<15} {}".format(ipv4_address, e))


async def check_ip_group(
        ipv4_8bit_rangable: str="",
        sslctx: ssl.SSLContext=None,
        certificates: multiprocessing.Queue=None
    ) -> None:
    """
    Attempts to connect to all IPv4 addresses in a sepecific range and collect
    any certificates presented by the peers during the handshakes.

    Args:
        ipv4_8bit_rangable (str): A formattable IPv4 address with the last 8
            bits unset.
        sslctx (ssl.SSLContext): The SSL context used to identify the handshake
            protocol to use during the attempted connection.
        certificates (multiprocessing.Queue): Thread-safe queue to store any
            certificate presented by the peer during the SSL handshake.

    """
    # A list of ensured futures for collection of certificates
    tasks               =   []
    octet_bits          =   0b0000_0000

    # Create IPv4 group tasks to collect certificates
    while (octet_bits <= 0b1111_1111):

        # Create IPv4 address to attempt both handshakes on
        ipv4_address    =   ipv4_8bit_rangable.format(octet_bits)

        # Append the SSL port scan task
        if (SCAN_SSL_PORT):
            tasks.append(
                    asyncio.ensure_future(
                            ssl_future(ipv4_address, SSL_PORT, sslctx)
                    )
            )

        # Append the SSH port scan task
        if (SCAN_SSH_PORT):
            tasks.append(
                    asyncio.ensure_future(
                            ssh_future(ipv4_address, SSH_PORT)
                    )
            )

        # Add one bit to the octet group until the octet group is all ones
        octet_bits      +=  0b0000_0001

    # Collect any certificate in the output of the tasks
    store_certificates(await asyncio.gather(*tasks), certificates)


def ipv4_certificate_scan(
        addresses: multiprocessing.Queue=None,
        certificates: multiprocessing.Queue=None,
        wait_for_queue: bool=True
    ) -> None:
    """
    Process execution method for each process in the process pool.

    Each process will create an event loop which will then monitor many
    simultaneous connections and record any certificate presented during the
    handshaking process with the peer.

    Args:
        addresses (multiprocessing.Queue): Thread-safe queue for coordinating
            the distrubition of ip addresses across the entire process pool.
        certificates (multiprocessing.Queue): Thread-safe queue used to store
            certificates collected during the handshaking process with the peer.
        wait_for_queue (bool): Determine if the read from the queue should block
            until there is something available.

    """
    # Maintain the socket ssl wrapper for each connection, reduces cpu usage
    sslctx              =   ssl.SSLContext(ssl.PROTOCOL_TLS)

    # Run forever
    while True:

        # Stores the current address block being checked
        address         =   None

        # Asynchronously check an IP range for certificates
        try:
            address     =   addresses.get(wait_for_queue)
            loop        =   asyncio.get_event_loop()
            future      =   asyncio.ensure_future(
                                check_ip_group(address, sslctx, certificates)
                            )

            # Check the IPv4 addresses for certs
            loop.run_until_complete(future)

        # Break the main thread if the queue has been depleted
        except multiprocessing.queues.Empty:
            if (addresses.qsize() == 0): break

        # Record any error and continue to the next address group
        except Exception as e:

            # Cannot do a format shift when the address is NONE
            if (None != address):   log.error("{:<15} {}".format(address, e))
            else:                   log.error(e)


def consume_and_record(
        addresses: multiprocessing.Queue=None,
        certificates: multiprocessing.Queue=None
    ) -> None:
    """
    Main Process task to read the output of the processes of the thread pool
    and log the collected certificates.

    Args:
        addresses (multiprocessing.Queue): Thread-safe queue of generated ipv4
            addresses, used in the verification of depletion of resources.
        certificates (multiprocessing.Queue): Thread-safe queue of collected
            certificates from the process pool, this method extracts the
            collected certificates and records them for future processing.

    """
    # Avoid rare edge case where a process in the pool has consumed the last
    # certificate of the certificates queue and is attempting collection as the
    # certificate queue read of this process timeout outs.
    retried_queue = False

    # Continually read the information recorded by the process pool and log it
    while True:
        try:
            clog.info(certificates.get(True, timeout=CERT_QUEUE_READ_TIMEOUT))

        except multiprocessing.queues.Empty:
            if   (retried_queue     ==  True):  break
            elif (addresses.qsize() ==  0   ):  retried_queue = True

        except Exception as e:
            log.error("Main Process: {}".format(e))


def generate_addresses(queue: multiprocessing.Queue=None) -> None:
    """
    Generate IPv4 compatible addresses and place them into a thread-safe queue

    This method skips any generated IPv4 address that falls into the reserved
    address space. The generated IPv4 addresses are first placed into an array,
    the array is shuffled, then the elements of the array are placed into the
    thread-safe queue passed as a parameter.

    From Section 4 Summary Table of RFC5735 the Special Use (Reserved) IPv4
    address space is as follows:

        Address Block       Present Use                Reference
        ------------------------------------------------------------------
        0.0.0.0/8           "This" Network             RFC 1122, Section 3.2.1.3
        10.0.0.0/8          Private-Use Networks       RFC 1918
        127.0.0.0/8         Loopback                   RFC 1122, Section 3.2.1.3
        169.254.0.0/16      Link Local                 RFC 3927
        172.16.0.0/12       Private-Use Networks       RFC 1918
        192.0.0.0/24        IETF Protocol Assignments  RFC 5736
        192.0.2.0/24        TEST-NET-1                 RFC 5737
        192.88.99.0/24      6to4 Relay Anycast         RFC 3068
        192.168.0.0/16      Private-Use Networks       RFC 1918
        198.18.0.0/15       Network Interconnect
                            Device Benchmark Testing   RFC 2544
        198.51.100.0/24     TEST-NET-2                 RFC 5737
        203.0.113.0/24      TEST-NET-3                 RFC 5737
        224.0.0.0/4         Multicast                  RFC 3171
        240.0.0.0/4         Reserved for Future Use    RFC 1112, Section 4
        255.255.255.255/32  Limited Broadcast          RFC 919,  Section 7
                                                       RFC 922,  Section 7

    Args:
        queue (Queue): Specifies a queue to place generated addresses. Addresses
            of the queue are formatted as follows: '123.123.123.{}'

    """
    # All reserved IP network addresses according to RFC5735
    IPV4_RES_ADDR_SPACE     =   [
                                    ip_network("100.64.0.0/10"),
                                    ip_network("169.254.0.0/16"),
                                    ip_network("192.0.0.0/24"),
                                    ip_network("192.0.2.0/24"),
                                    ip_network("192.88.99.0/24"),
                                    ip_network("192.168.0.0/16"),
                                    ip_network("198.18.0.0/15"),
                                    ip_network("198.51.100.0/24"),
                                    ip_network("203.0.113.0/24"),
                                ]

    # Holds the octet of IPv4 addresses that need further analysis
    IPV4_FIRST_RES_OCTET    =   [   100, 168, 172, 192, 198, 203   ]

    # Holds generated IPv4 address
    ipv4_8bit_rangables     =   []

    # Generate the first octet bit group
    for octet_bits_1 in range(IPV4_ADDR_START, IPV4_ADDR_END):

        # IPv4 Addresses with this value in the first octet are reserved
        if ((octet_bits_1 >= 224) or
            (octet_bits_1 == 0  ) or
            (octet_bits_1 == 10 ) or
            (octet_bits_1 == 127)
        ):
            continue

        # Generate the second octet bit group
        for octet_bits_2 in range(256):

            # Generate the third octet bit group
            for octet_bits_3 in range(256):

                # String formattable allows the end 8 bits to be easily set
                ipv4_8bit_rangable  =   "%d.%d.%d.{}" % (octet_bits_1,
                                                         octet_bits_2,
                                                         octet_bits_3)

                # Ensure proper exclusion of reserved IPv4 addresses
                if ((octet_bits_1 in IPV4_FIRST_RES_OCTET) and
                    any(
                        ip_address(ipv4_8bit_rangable.format(0b0000_0000))
                        in network for network in IPV4_RES_ADDR_SPACE
                    )
                ):
                    continue

                ipv4_8bit_rangables.append(ipv4_8bit_rangable)


    # Prevent consecutive IPv4 scans (NOTE: European ISP concern)
    log.info("Main Process: Shuffling addresses.")
    random.shuffle(ipv4_8bit_rangables)

    # Add the shuffled items into the thread-safe queue
    log.info("Main Process: Queueing shuffled addresses.")
    for ipv4_8bit_rangable in ipv4_8bit_rangables: queue.put(ipv4_8bit_rangable)


if (__name__ == "__main__"):
    """
    If successful, the main process will execute the following steps:
        1.  Initialize two thread safe queues and a process pool.
        2.  Generate IPv4 addresses in the specified range.
        3.  Consume and record the certificates collected by the process pool.
        4.  Terminate and clean up the process pool.

    """
    # Thread-Safe queues handle the coordination and the distribution of IPv4
    # addresses and certificates across the process pool
    ipv4_addresses  =   multiprocessing.Queue()
    certificates    =   multiprocessing.Queue()

    # Process pool is responsible for scanning ipv4 addresses for certificates
    log.info("Main Process: Building Process Pool.")
    process_pool    =   multiprocessing.Pool(
                                                PROCESS_POOL_SIZE,
                                                ipv4_certificate_scan,
                                                (ipv4_addresses, certificates, )
                        )

    # Generate IPv4 compatible addresses for the process pool to consume
    log.info("Main Process: Starting Address Generation.")
    generate_addresses(ipv4_addresses)

    # Consume and record the certificates collected by the process pool
    log.info("Main Process: Starting Collection Storage.")
    consume_and_record(ipv4_addresses, certificates)

    # Clean up the thread pool and exit gracefully
    log.info("Main Process: IPv4 Queue Depleted, Terminating Process Pool.")
    process_pool.terminate()
    process_pool.join()
