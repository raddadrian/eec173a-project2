import socket
import random
import struct
import io
import time

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


def main():
    tldResponse = ""
    authResponse = ""
    rootResponse = ""

    # Ask for site we want the IP to
    siteName = input("What site do you want the IP for: ")

    # Build DNS request
    request = createQuery(siteName)
    # print(request)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.settimeout(10)

        for hostName in rootServers:
            try:
                startTime = time.time()
                endTime = time.time()

                client_socket.sendto(request, (rootServers[hostName], 53))

                response, addr = client_socket.recvfrom(1024)

                if response:
                    # unpack DNS record + type + ip addresses
                    print(f"Response from: {hostName}")
                    rootResponse = response
                    break
            except socket.timeout:
                print(f"No response from: {hostName}")

        if rootResponse:
            header, question, answer, ns_records, ipv4, ipv6 = decodeResponse(
                rootResponse
            )
            print("\nRoot Server Response:")
            print(f"Header: {header}")
            print(f"Question: {question}")
            print(f"Answer: {answer}")
            print(f"TLD Servers: {ns_records}")
            print(f"Additional: {ipv4} {ipv6}")

            for hostName in ipv4:
                try:
                    client_socket.sendto(request, (hostName["ip"], 53))

                    response, addr = client_socket.recvfrom(1024)

                    if response:
                        # unpack DNS record + type + ip addresses
                        print(f"Response from: {hostName}")
                        tldResponse = response
                        break
                except socket.timeout:
                    print(f"No response from: {hostName}")
            if tldResponse:
                header, question, answer, ns_records, ipv4, ipv6 = decodeResponse(
                    tldResponse
                )
                print("\nTLD Server Response:")
                print(f"Header: {header}")
                print(f"Question: {question}")
                print(f"Answer: {answer}")
                print(f"TLD Servers: {ns_records}")
                print(f"Additional: {ipv4} {ipv6}")

                for hostName in ipv4:
                    try:
                        client_socket.sendto(request, (hostName["ip"], 53))

                        response, addr = client_socket.recvfrom(1024)

                        if response:
                            # unpack DNS record + type + ip addresses
                            print(f"Response from: {hostName}")
                            authResponse = response
                            break
                    except socket.timeout:
                        print(f"No response from: {hostName}")
                if authResponse:
                    header, question, answer, ns_records, ipv4, ipv6 = decodeResponse(
                        authResponse
                    )

                    print("\nAuthoritative Server Response:")
                    endTime = time.time()
                    rtt = round(endTime - startTime, 5)
                    print(
                        f"The RTT between this machine and the public DNS resolver was {rtt} seconds"
                    )
                    
                    print(f"Header: {header}")
                    print(f"Question: {question}")
                    print(f"Answer: {answer}")
                    print(f"TLD Servers: {ns_records}")
                    print(f"Additional: {ipv4} {ipv6}")

                    with socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM
                    ) as tcp_socket:
                        for hostName in answer:
                            try:
                                tcp_socket.connect((hostName["ip"], 80))

                                startTime = time.time()
                                endTime = time.time()

                                httpReq = (
                                    f"GET / HTTP/1.1\r\n"
                                    f"Host: {hostName["name"]}\r\n"
                                    "Connection: close\r\n"
                                    "User-Agent: Custom-Client/1.0\r\n"
                                    "Accept: */*\r\n"
                                    "\r\n"
                                )

                                tcp_socket.sendall(httpReq.encode())

                                response = b""
                                while True:
                                    data = tcp_socket.recv(4096)

                                    if data:
                                        response += data
                                    else:
                                        endTime = time.time()
                                        break

                                if response:
                                    response = response.decode("utf-8")

                                    status, header, body = response.partition(
                                        "\r\n\r\n"
                                    )

                                    file = "output.html"

                                    with open(file, "w", encoding="utf-8") as f:
                                        f.write(body)

                                    rtt = round(endTime - startTime, 5)

                                    print(status)
                                    print(
                                        f"The RTT between this machine and the {hostName["name"]}'s server was {rtt} seconds"
                                    )

                                    break

                            except socket.timeout:
                                print(f"No response from: {hostName}")

                            tcp_socket.close()
                else:
                    print("No response from authoritative server")
            else:
                print("No response from any TLD server")
        else:
            print("No response from any root server")


if __name__ == "__main__":
    main()


#
# for hostName in rootServers:
# send DNS request to rootServers(hostName)
# if response
# print connected to hostName at hostIP
# unpack to get DNS records + type and ip addresses
# Use the IP to go to next server -> repeat
# else if timeout
# go to next hostName
