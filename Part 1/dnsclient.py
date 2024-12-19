import socket
import random
import struct
import io
import time

# Existing rootServers dictionary remains unchanged...
rootServers = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}

def createQuery(hostName, typeDNS=1, classDNS=1):
    # Header
    id = random.randint(0, 65535)
    flags = 0x0100
    numQuestions = 1
    numAnswers = 0
    numAuthorities = 0
    numAdditionals = 0

    header = struct.pack(
        "!HHHHHH", id, flags, numQuestions, numAnswers, numAuthorities, numAdditionals
    )

    # Question
    encodedName = b""
    for part in hostName.encode("utf-8").split(b"."):
        encodedName += bytes([len(part)]) + part
    encodedName += b"\x00"

    question = encodedName + struct.pack("!HH", typeDNS, classDNS)

    return header + question


def decodeName(response):
    parts = []
    try:
        while True:
            length = response.read(1)
            if not length:  # Check for EOF
                break
            length = length[0]
            if length == 0:
                break

            if length & 0xC0:  # Compression pointer
                pointer_bytes = bytes([length & 0x3F]) + response.read(1)
                pointer = struct.unpack("!H", pointer_bytes)[0]
                current_pos = response.tell()
                response.seek(pointer)
                result = decodeName(response)
                response.seek(current_pos)
                parts.append(result.decode("utf-8"))
                break
            else:
                part = response.read(length)
                if not part:  # Check for EOF
                    break
                parts.append(part.decode("utf-8"))

    except Exception as e:
        print(f"Error in decodeName: {e}")
        return b""

    return ".".join(parts).encode("utf-8")

def decodeResponse(responseData):
    response = io.BytesIO(responseData)

    # Header
    id, flags, numQuestions, numAnswers, numAuthorities, numAdditionals = struct.unpack(
        "!HHHHHH", response.read(12)
    )

    header = {
        "id": id,
        "flags": flags,
        "numQuestions": numQuestions,
        "numAnswers": numAnswers,
        "numAuthorities": numAuthorities,
        "numAdditionals": numAdditionals,
    }

    # Question
    name = decodeName(response)
    typeDNS, classDNS = struct.unpack("!HH", response.read(4))

    question = {"name": name, "type": typeDNS, "class": classDNS}

    # Answer
    answers = []
    for _ in range(numAnswers):
        try:
            answer_name = decodeName(response)
            record_data = response.read(10)
            if len(record_data) < 10:
                break

            rType, rClass, ttl, rDataLength = struct.unpack("!HHIH", record_data)
            rData = response.read(rDataLength)
            # A Record
            if rType == 1:
                rData = ".".join(str(b) for b in rData)
            # AAAA Record
            elif rType == 28:
                ipv6_parts = [rData[i : i + 2].hex() for i in range(0, 16, 2)]
                rData = ":".join(ipv6_parts)

            answers.append(
                {
                    "name": answer_name.decode("utf-8"),
                    "type": rType,
                    "class": rClass,
                    "ttl": ttl,
                    "ip": rData,
                }
            )
        except Exception as e:
            print(f"Error parsing answer: {e}")
            break

    # Authority
    auth_records = []
    for _ in range(numAuthorities):
        try:
            auth_name = decodeName(response)
            auth_data = response.read(10)
            if len(auth_data) < 10:
                break

            rType, rClass, ttl, rDataLength = struct.unpack("!HHIH", auth_data)
            # NS Record
            if rType == 2:
                tld_name = decodeName(response)
                auth_records.append(
                    {
                        "domain": auth_name.decode("utf-8"),
                        "ns": tld_name.decode("utf-8"),
                    }
                )
            else:
                response.read(rDataLength)
        except Exception as e:
            print(f"Error parsing authority: {e}")
            break

    # Additional
    ipv4 = []
    ipv6 = []
    for _ in range(numAdditionals):
        try:
            add_name = decodeName(response)
            add_data = response.read(10)
            if len(add_data) < 10:
                break

            rType, rClass, ttl, rDataLength = struct.unpack("!HHIH", add_data)
            record_info = {"name": add_name.decode("utf-8"), "type": rType, "ttl": ttl}

            # A Record (IPv4)
            if rType == 1:
                ip_bytes = response.read(rDataLength)
                record_info["ip"] = ".".join(str(b) for b in ip_bytes)
                ipv4.append(record_info)
            # AAAA Record (IPv6)
            elif rType == 28:
                ip_bytes = response.read(rDataLength)
                ipv6_parts = [ip_bytes[i : i + 2].hex() for i in range(0, 16, 2)]
                record_info["ip"] = ":".join(ipv6_parts)
                ipv6.append(record_info)
            else:
                response.read(rDataLength)

        except Exception as e:
            print(f"Error parsing additional record: {e}")
            break

    return header, question, answers, auth_records, ipv4, ipv6

def query_dns_server(client_socket, request, servers, server_type=""):
    """
    Query DNS servers and return the first successful response
    """
    response = None
    responding_server = None

    for server in servers:
        try:
            start_time = time.time()
            
            server_ip = servers[server] if isinstance(servers, dict) else server["ip"]
            client_socket.sendto(request, (server_ip, 53))
            
            response, addr = client_socket.recvfrom(1024)
            
            if response:
                end_time = time.time()
                rtt = round(end_time - start_time, 5)
                print(f"The RTT between this machine and the server was {rtt} seconds")
                responding_server = server
                break
                
        except socket.timeout:
            print(f"No response from: {server}")
    
    return response, responding_server

def process_dns_response(response, server_type):
    """
    Process and print DNS response details
    """
    if not response:
        print(f"No response from any {server_type} server")
        return None, None, None
        
    header, question, answer, ns_records, ipv4, ipv6 = decodeResponse(response)
    
    print(f"\n{server_type} Server Response:")
    print(f"Header: {header}")
    print(f"Question: {question}")
    print(f"Answer: {answer}")
    print(f"Name Servers: {ns_records}")
    print(f"Additional: {ipv4} {ipv6}")
    
    return answer, ns_records, ipv4

def make_http_request(answer):
    """
    Make HTTP request to the resolved IP address
    """
    if not answer:
        return
        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        for host in answer:
            try:
                tcp_socket.connect((host["ip"], 80))
                start_time = time.time()

                http_request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host['name']}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: Custom-Client/1.0\r\n"
                    "Accept: */*\r\n"
                    "\r\n"
                )

                tcp_socket.sendall(http_request.encode())
                
                response = receive_http_response(tcp_socket)
                if response:
                    end_time = time.time()
                    process_http_response(response, host, start_time, end_time)
                    break

            except socket.timeout:
                print(f"No response from: {host}")
            except Exception as e:
                print(f"Error connecting to {host['name']}: {e}")

def receive_http_response(tcp_socket):
    """
    Receive and concatenate HTTP response data
    """
    response = b""
    while True:
        data = tcp_socket.recv(4096)
        if not data:
            break
        response += data
    return response

def process_http_response(response, host, start_time, end_time):
    """
    Process HTTP response and save to file
    """
    response = response.decode("utf-8")
    status, header, body = response.partition("\r\n\r\n")
    
    with open("output2.html", "w", encoding="utf-8") as f:
        f.write(body)
    
    rtt = round(end_time - start_time, 5)
    print(status)
    print(f"The RTT between this machine and {host['name']}'s server was {rtt} seconds")

def resolve_domain(site_name):
    """
    Main domain resolution function
    """
    request = createQuery(site_name)
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.settimeout(10)
        
        # Query root servers
        root_response, _ = query_dns_server(client_socket, request, rootServers, "Root")
        _, _, root_ipv4 = process_dns_response(root_response, "Root")
        
        if not root_ipv4:
            return
            
        # Query TLD servers
        tld_response, _ = query_dns_server(client_socket, request, root_ipv4, "TLD")
        _, _, tld_ipv4 = process_dns_response(tld_response, "TLD")
        
        if not tld_ipv4:
            return
            
        # Query authoritative servers
        auth_response, _ = query_dns_server(client_socket, request, tld_ipv4, "Authoritative")
        auth_answer, _, _ = process_dns_response(auth_response, "Authoritative")
        
        if not auth_answer:
            return
            
        # Make HTTP request to resolved IP
        make_http_request(auth_answer)

def main():
    site_name = input("What site do you want the IP for: ")
    resolve_domain(site_name)

if __name__ == "__main__":
    main()