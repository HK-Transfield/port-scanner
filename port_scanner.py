import socket
import common_ports


def get_open_ports(target, port_range, verbose=False):
    open_ports = []
    str_verbose = ""

    for port in range(port_range[0], port_range[1]):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((socket.gethostbyname(target), port))

        if result == 0:
            print(port)
            open_ports.append(port)
        s.close()

    if verbose == True:
        str_verbose = "Open ports for " + str(socket.gethostbyaddr(target))
    else:
        return(open_ports)

# #!/usr/bin/python3

# import nmap

# scanner = nmap.PortScanner()

# #scanner started
# print("Greetings and salutation everyone! This is a simple nmap automation tool")
# print("---------------------------------------------------------------------------")

# ip_addr = input("\n\nPlease enter the IP address you want to scan: ")
# print("The IP you entered is: ", ip_addr)
# type(ip_addr)


# resp = input("""\nPLease enter the type of scan you want to run
#             1. SYN-ACK scan
#             2. UDP scan
#             3. Comprehensive scan\n""")
# print("You have selected: ", resp)

# if resp == "1":
#     print("Nmap Version: ", scanner.nmap_version())

#     #provide nmap, address, and arguements
#     scanner.scan(ip_addr, "1-1024", "-v -sS")
#     print(scanner.scaninfo())
#     print("IP status: ", scanner[ip_addr].state())
#     print(scanner[ip_addr].all_protocols())
#     print("Open Ports: ", scanner[ip_addr]["tcp"].keys())
# elif resp == "2":
#     print("Nmap Version: ", scanner.nmap_version())

#     #provide nmap, address, and arguements
#     scanner.scan(ip_addr, "1-1024", "-v -sU")
#     print(scanner.scaninfo())
#     print("IP status: ", scanner[ip_addr].state())
#     print(scanner[ip_addr].all_protocols())
#     print("Open Ports: ", scanner[ip_addr]["udp"].keys())
# elif resp == "3":
#     print("Nmap Version: ", scanner.nmap_version())

#     #provide nmap, address, and arguements
#     scanner.scan(ip_addr, "1-1024", "-v -sS -sV -sC -A -O")
#     print(scanner.scaninfo())
#     print("IP status: ", scanner[ip_addr].state())
#     print(scanner[ip_addr].all_protocols())
#     print("Open Ports: ", scanner[ip_addr]["tcp"].keys())
# else:
#     print("Please enter a valid option")
