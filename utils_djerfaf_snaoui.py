import math

hex_digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
              'A', 'B', 'C', 'D', 'E', 'F',
              'a', 'b', 'c', 'd', 'e', 'f']

hex_decimal = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6,
               '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13,
               'e': 14, 'f': 15, 'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15}

hex_binary = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101', '6': '0110',
              '7': '0111', '8': '1000', '9': '1001', 'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101',
              'e': '1110', 'f': '1111', 'A': '1010', 'B': '1011', 'C': '1100', 'D': '1101', 'E': '1110', 'F': '1111'}

textLines = []


def conversion_hex_to_decimal(x):
    output: int = 0
    p: int = len(x)
    for i in x:
        output += int(hex_decimal.get(i) * math.pow(16, p - 1))
        p -= 1
    return output


def conversion_binary_to_decimal(x):
    output: int = 0
    p: int = len(x)
    for i in x:
        output += int(int(i) * math.pow(2, p - 1))
        p -= 1
    return output


def conversion_hex_to_binary(x):
    output: str = ""
    for i in x:
        output += hex_binary.get(i)
    return output


def get_list_of_trams(filepath):
    list_cleaned: list[str] = []
    with open(filepath, 'r') as file:
        var = file.read().splitlines()
        number_of_lines = len(var)
        for i in range(number_of_lines):
            line_i = var[i]
            list_cleaned.append(line_i[7:54])

        # now we have a list that contains messages only
        # now we are going to extract the trams in each list so, we will have a list of lists

        trame_total = ""
        for message in list_cleaned:
            for character in message:
                if character in hex_digits:
                    trame_total += character

        list_trams = []
        get_frames(list_trams, trame_total)
        return list_trams


def get_frames(list_trams, message):
    type_ethernet = message[24:28]
    if type_ethernet == "0800":
        length_trame_i = message[32: 32 + 4]
        length_decimal_trame_i = conversion_hex_to_decimal(length_trame_i)
        cut = length_decimal_trame_i * 2 + 4 + 6 * 2 * 2
    if type_ethernet == "0806":
        cut = 42 * 2

    trame_i: str = message[0: cut]
    list_trams.append(trame_i)
    new_message = message[cut:]
    if len(new_message) > 0:
        get_frames(list_trams, new_message)


def get_mac(message):
    output = ""
    i = 0
    while i < 12:
        octet = message[i:i + 2]
        output += octet
        output += ':'
        i += 2
    output = output[:-1]
    return output


def get_ip(message):
    output = ""
    i = 0
    while i < 8:
        octet = message[i:i + 2]
        decimal_transformation = conversion_hex_to_decimal(octet)
        output += str(decimal_transformation)
        output += '.'
        i += 2
    output = output[:-1]
    return output


def get_http_message(message):
    output = ""
    i = 0
    while i < len(message):
        octet = message[i:i + 2]
        decimal_transformation = conversion_hex_to_decimal(octet)
        output += chr(decimal_transformation)
        i += 2
    return output


def displaying(tram, counter, f):
    f.write("\n#################################################\n\n")
    print(f"Frame {counter} : ")
    text_line = "Frame " + str(counter) + " : \n"
    f.write(text_line)
    print()
    i = 0
    nbr_octet = 0
    output = ""
    total_length = len(tram)

    while i < total_length:
        octet = tram[i:i + 2]
        output += octet
        nbr_octet += 1
        if nbr_octet == 16:
            print(output)
            f.write(output)
            f.write("\n")
            output = ""
            nbr_octet = 0
        else:
            output += " "
        i += 2
    print(output)
    f.write(output)
    f.write("\n")
    print()


def analyse_tcp_options(message, number, f):
    ###############################################################################
    ############################ analyse TCP Options ###############################
    ###############################################################################

    ###############################################################################
    # reference : https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml ###
    ###############################################################################
    kind = message[0:2]
    if kind == '00':
        opt_len = 1
        print(f"\t\tOption {number} Type = 0x{kind} : End of Option List")
        f.write(f"\t\tOption {number} Type = 0x{kind} : End of Option List\n")
    elif kind == '01':
        opt_len = 1
        print(f"\t\tOption {number} Type = 0x{kind} : No Operation")
        f.write(f"\t\tOption {number} Type = 0x{kind} : No Operation\n")
    elif kind == '02':
        opt_len = conversion_hex_to_decimal(message[2:4])
        mss = message[4:8]
        print(f"\t\tOption {number} Type =  0x{kind} : Maximum Segment Size")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Maximum Segment Size\n")
        print(f"\t\t--> MSS = 0x{mss}")
        f.write(f"\t\t--> MSS = 0x{mss}\n")

    elif kind == '03':
        opt_len = conversion_hex_to_decimal(message[2:4])
        shift = message[4:5]
        print(f"\t\tOption {number} Type =  0x{kind} : Window Scale WSopt")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Window Scale WSopt\n")
        print(f"\t\t--> Shift = 0x{shift}")
        f.write(f"\t\t--> Shift = 0x{shift}\n")
    elif kind == '04':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Sack")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Sack\n")
    elif kind == '05':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Sack-Permitted")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Sack-Permitted\n")
    elif kind == '06':
        opt_len = conversion_hex_to_decimal(message[2:4])
        info = message[4:12]
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Echo")
        f.write(f"\t\tOption {number} Type =  0x{kind} : TCP Echo\n")
        print(f"\t\t--> Info to be echoed = 0x{info}")
        f.write(f"\t\t--> Info to be echoed = 0x{info}\n")
    elif kind == '07':
        opt_len = conversion_hex_to_decimal(message[2:4])
        info = message[4:12]
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Echo Reply")
        f.write(f"\t\tOption {number} Type =  0x{kind} : TCP Echo Reply\n")
        print(f"\t\t--> Echoed info= 0x{info}")
        f.write(f"\t\t--> Echoed info= 0x{info}\n")
    elif kind == '08':
        opt_len = conversion_hex_to_decimal(message[2:4])
        time_stamp_value = message[4:12]
        time_echo_reply_value = message[12:20]
        print(f"\t\tOption {number} Type =  0x{kind} : Time Stamp")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Time Stamp\n")
        print(f"\t\t--> Time Stamp Value = 0x{time_stamp_value}")
        f.write(f"\t\t--> Time Stamp Value = 0x{time_stamp_value}\n")
        print(f"\t\t--> Time Echo Reply Value = 0x{time_echo_reply_value}")
        f.write(
            f"\t\t--> Time Echo Reply Value = 0x{time_echo_reply_value}\n")
    elif kind == '09':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : TCP POC-permitted")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP POC-permitted\n")
    elif kind == '0A' or kind == '0a':
        opt_len = conversion_hex_to_decimal(message[2:4])
        info = conversion_hex_to_binary(message[4:5])
        start = info[0:1]
        end = info[1:2]
        filler = info[2:8]
        print(f"\t\tOption {number} Type =  0x{kind} : TCP POC-service-profile")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP POC-service-profile\n")
        print(f"\t\t--> Start Flag = {start}")
        f.write(f"\t\t--> Start Flag = {start}\n")
        print(f"\t\t--> End Flag = {end}")
        f.write(f"\t\t--> End Flag = {end}\n")
        print(f"\t\t--> Filler = {filler}")
        f.write(f"\t\t--> Filler = {filler}\n")
    elif kind == '0B' or kind == '0b':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : CC")
        f.write(f"\t\tOption {number} Type =  0x{kind} : CC\n")
    elif kind == '0C' or kind == '0c':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : CC New")
        f.write(f"\t\tOption {number} Type =  0x{kind} : CC New\n")
    elif kind == '0D' or kind == '0d':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : CC Echo")
        f.write(f"\t\tOption {number} Type =  0x{kind} : CC Echo\n")
    elif kind == '0E' or kind == '0e':
        opt_len = conversion_hex_to_decimal(message[2:4])
        checksum = message[4:5]
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Alternate Checksum Request")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP Alternate Checksum Request\n")
        print(f"\t\t--> Checksum = {checksum}")
        f.write(f"\t\t--> Checksum = {checksum}\n")
    elif kind == '0F' or kind == '0f':
        opt_len = conversion_hex_to_decimal(message[2:4])
        data = message[4:4 + opt_len - 2]
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Alternate Checksum Data")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP Alternate Checksum Data\n\n")
        print(f"\t\t--> Checksum Data = 0x{data}")
        f.write(f"\t\t--> Checksum Data = 0x{data}\n")
    elif kind == '10':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Skeeter")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Skeeter\n")
    elif kind == '11':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Blubba")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Blubba\n")
    elif kind == '12':
        opt_len = conversion_hex_to_decimal(message[2:4])
        check = message[4:5]
        print(f"\t\tOption {number} Type =  0x{kind} : Trailer Checksum")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Trailer Checksum\n")
        print(f"\t\t--> Checksum = {check}")
        f.write(f"\t\t--> Checksum = {check}\n")
    elif kind == '13':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : MD5 Signature")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : MD5 Signature\n")
    elif kind == '14':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : SCPS Capabilities")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : SCPS Capabilities\n")
    elif kind == '15':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Selective Negative Acknowledgments")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Selective Negative Acknowledgments\n")
    elif kind == '16':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Record Boundaries")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Record Boundaries\n")
    elif kind == '17':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Corruption experienced")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Corruption experienced\n")
    elif kind == '18':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : SNAP")
        f.write(f"\t\tOption {number} Type =  0x{kind} : SNAP\n")
    elif kind == '19':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Unassigned")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Unassigned\n")
    elif kind == '1A' or kind == '1a':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Compression Filter")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP Compression Filter\n")
    elif kind == '1B' or kind == '1b':
        opt_len = conversion_hex_to_decimal(message[2:4])
        data = conversion_hex_to_binary(message[4:10])
        resv = data[0:4]
        rate_request = data[4:8]
        ttl_diff = data[8:16]
        qs_nonce = data[16:46]
        r = data[46:48]
        print(f"\t\tOption {number} Type =  0x{kind} : Quick-Start Response")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Quick-Start Response\n")
        print(f"\t\t--> Resv = {resv}")
        f.write(f"\t\t--> Resv = {resv}\n")
        print(f"\t\t--> Rate Request = {rate_request}")
        f.write(f"\t\t--> Rate Request = {rate_request}\n")
        print(f"\t\t--> TTL Diff = {ttl_diff}")
        f.write(f"\t\t--> TTL Diff = {ttl_diff}\n")
        print(f"\t\t--> QS Nonce = {qs_nonce}")
        f.write(f"\t\t--> QS Nonce = {qs_nonce}\n")
        print(f"\t\t--> R = {r}")
        f.write(f"\t\t--> R = {r}\n")
    elif kind == '1C' or kind == '1c':
        opt_len = conversion_hex_to_decimal(message[2:4])
        data = conversion_hex_to_binary(message[4:6])
        g = data[0:1]
        user_timeout = data[1:]
        print(f"\t\tOption {number} Type =  0x{kind} : User Timeout")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : User Timeout\n")
        print(f"\t\t--> g = {g}")
        f.write(f"\t\t--> g = {g}\n")
        print(f"\t\t--> User Timeout = {user_timeout}")
        f.write(f"\t\t--> User Timeout = {user_timeout}\n")
    elif kind == '1D' or kind == '1d':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Authentication")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP Authentication\n")
    elif kind == '1E' or kind == '1e':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Multipath TCP")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Multipath TCP\n")
    elif kind == '22':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : TCP Fast Open Cookie")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : TCP Fast Open Cookie\n")
    elif kind == '45':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Encryption Negotiation")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Encryption Negotiation\n")
    elif kind == 'AC' or kind == 'ac' or kind == 'Ac' or kind == 'aC':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Accurate ECN Order 0")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Accurate ECN Order 0\n")
    elif kind == 'AD' or kind == 'ad' or kind == 'Ad' or kind == 'aD':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Accurate ECN Order 1")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Accurate ECN Order 1\n")
    elif kind == 'FD' or kind == 'fd' or kind == 'Fd' or kind == 'fD':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment 1")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment 1\n")
    elif kind == 'FE' or kind == 'fe' or kind == 'Fe' or kind == 'fE':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment 2")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment 2\n")
    else:
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Reserved !")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Reserved !\n")

    number += 1

    if opt_len == 0 or opt_len == 1:
        new_message = message[2:]
    else:
        new_message = message[2 * opt_len:]

    if len(new_message) > 1 and kind != '00':
        analyse_tcp_options(new_message, number, f)


def record_route(message, number_ips_max, current_ip_number, f):
    if current_ip_number <= number_ips_max:
        current_ip = get_ip(message[0:8])
        print(f"\t\t--> ip n{current_ip_number} : {current_ip}")
        f.write(f"\t\t--> ip n{current_ip_number} : {current_ip}\n")
        current_ip_number += 1
        record_route(message[8:], number_ips_max, current_ip_number, f)


def analyse_ip_options(message, number, f):
    ###############################################################################
    ############################ analyse IP Options ###############################
    ###############################################################################

    ###############################################################################
    # reference : https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml ###
    ###############################################################################

    kind = message[0:2]
    if kind == '00':
        opt_len = 1
        print(f"\t\tOption {number} Type = 0x{kind} : End of Option List")
        f.write(
            f"\t\tOption {number} Type = 0x{kind} : End of Option List\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")

    elif kind == '01':
        opt_len = 1
        print(f"\t\tOption {number} Type = 0x{kind} : No Operation")
        f.write(f"\t\tOption {number} Type = 0x{kind} : No Operation\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '07':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Record Route")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Record Route\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        record_route(message[6:6 + opt_len - 4], (opt_len - 3) / 4, 1, f)
    elif kind == '0A' or kind == '0a':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : ZSU - Experimental Measurement")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : ZSU - Experimental Measurement\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '0B' or kind == '0b':
        opt_len = conversion_hex_to_decimal(message[2:4])
        value = message[4:5]
        print(f"\t\tOption {number} Type =  0x{kind} : Probe MTU")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Probe MTU\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        print(f"\t\t--> Checksum = {value}")
        f.write(f"\t\t--> Checksum = {value}\n")
    elif kind == '0C' or kind == '0c':
        opt_len = conversion_hex_to_decimal(message[2:4])
        value = message[4:5]
        print(f"\t\tOption {number} Type =  0x{kind} : Reply MTU")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Reply MTU\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        print(f"\t\t--> Checksum = {value}")
        f.write(f"\t\t--> Checksum = {value}\n")
    elif kind == '0F' or kind == '0f':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Encode")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Encode\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '19':
        opt_len = conversion_hex_to_decimal(message[2:4])
        data = conversion_hex_to_binary(message[4:10])
        resv = data[0:4]
        rate_request = data[4:8]
        ttl_diff = data[8:16]
        qs_nonce = data[16:46]
        r = data[46:48]
        print(f"\t\tOption {number} Type =  0x{kind} : Quick-Start")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Quick-Start\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        print(f"\t\t--> Resv = {resv}")
        f.write(f"\t\t--> Resv = {resv}\n")
        print(f"\t\t--> Rate Request = {rate_request}")
        f.write(f"\t\t--> Rate Request = {rate_request}\n")
        print(f"\t\t--> TTL Diff = {ttl_diff}")
        f.write(f"\t\t--> TTL Diff = {ttl_diff}\n")
        print(f"\t\t--> QS Nonce = {qs_nonce}")
        f.write(f"\t\t--> QS Nonce = {qs_nonce}\n")
        print(f"\t\t--> R = {r}")
        f.write(f"\t\t--> R = {r}\n")
    elif kind == '1E' or kind == '1e':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '44':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Time Stamp")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Time Stamp\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '52':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Traceroute")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Traceroute\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '5E' or kind == '5e':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Security")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Security\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '82':
        opt_len = conversion_hex_to_decimal(message[2:4])
        classification_level = conversion_hex_to_binary(message[4:6])
        if classification_level == "00000001":
            classification_lvl = "(Reserved 4)"
        elif classification_level == "00111101":
            classification_lvl = "Top Secret"
        elif classification_level == "01011010":
            classification_lvl = "Secret"
        elif classification_level == "10010110":
            classification_lvl = "Confidential"
        elif classification_level == "01100110":
            classification_lvl = "(Reserved 3)"
        elif classification_level == "11001100":
            classification_lvl = "(Reserved 2)"
        elif classification_level == "10101011":
            classification_lvl = "Unclassified"
        elif classification_level == "11110001":
            classification_lvl = "(Reserved 1)"
        else:
            classification_lvl = ""
        print(f"\t\tOption {number} Type =  0x{kind} : Reply MTU")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Reply MTU\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        print(f"\t\t--> Classification level = 0x{classification_level} {classification_lvl}")
        f.write(
            f"\t\t--> Classification level = 0x{classification_level} {classification_lvl}\n")
    elif kind == '83':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Loose Source and Record Route")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Loose Source and Record Route\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        record_route(message[6:6 + opt_len - 4], (opt_len - 3) / 4, 1, f)
    elif kind == '85':
        opt_len = conversion_hex_to_decimal(message[2:4])
        additional = message[4:8]
        print(f"\t\tOption {number} Type =  0x{kind} : Extended Security")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Extended Security\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        print(f"\t\t--> Additional Security Info = 0x{additional}")
        f.write(
            f"\t\t--> Additional Security Info = 0x{additional}\n")
    elif kind == '86':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Commercial IP Security")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Commercial IP Security\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '88':
        opt_len = conversion_hex_to_decimal(message[2:4])
        stream = message[4:12]
        print(f"\t\tOption {number} Type =  0x{kind} : Stream Identifier")
        f.write(f"\t\tOption {number} Type =  0x{kind} : Stream Identifier\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        print(f"\t\t--> Stream ID = 0x{stream}")
        f.write(f"\t\t--> Stream ID = 0x{stream}\n")
    elif kind == '89':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(f"\t\tOption {number} Type =  0x{kind} : Strict Source and Record Route")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Strict Source and Record Route\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
        record_route(message[6:6 + opt_len - 4], (opt_len - 3) / 4, 1, f)
    elif kind == '8E' or kind == '8e':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Experimental Access Control")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Experimental Access Control\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '90':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : IMI Traffic Descriptor")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : IMI Traffic Descriptor\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '91':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Extended Internet Protocol")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Extended Internet Protocol\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '91':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Address Extension")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Address Extension\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '94':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Router Alert")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Router Alert\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '95':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Selective Directed Broadcast")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Selective Directed Broadcast\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '97':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Dynamic Packet State")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Dynamic Packet State\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '98':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Upstream Multicast Packet")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Upstream Multicast Packet\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == '9E' or kind == '9e':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    elif kind == 'CD' or kind == 'cd' or kind == 'cD' or kind == 'Cd':
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : Experimental Flow Control")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : Experimental Flow Control\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")
    else:
        opt_len = conversion_hex_to_decimal(message[2:4])
        print(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment")
        f.write(
            f"\t\tOption {number} Type =  0x{kind} : RFC3692-style Experiment\n")
        print(f"\t\t-->Length = {opt_len}")
        f.write(f"\t\t-->Length = {opt_len}\n")

    number += 1

    if opt_len == 0 or opt_len == 1:
        new_message = message[2:]
    else:
        new_message = message[2 * opt_len:]

    if len(new_message) > 1 and kind != '00':
        analyse_ip_options(new_message, number, f)


def analyse_icmp(type_message, code, message, f):

    if type_message == "00" and code == "00":
        id_echo = message[0:4]
        num_seq = message[4:8]
        print(f"\t\t Echo Reply")
        f.write(f"\t\t Echo Reply\n")
        print(f"\t\t--> Identifier = 0x{id_echo}")
        f.write(f"\t\t--> Identifier = 0x{id_echo}\n")
        print(f"\t\t--> Sequence Number = 0x{num_seq}")
        f.write(f"\t\t--> Sequence Number = 0x{num_seq}\n")
    elif type_message == "03" and code == "00":
        print(f"\t\t Destination Network Unreachable")
        f.write(f"\t\t Destination Network Unreachable\n")
    elif type_message == "03" and code == "01":
        print(f"\t\t Destination Host Unreachable")
        f.write(f"\t\t Destination Host Unreachable\n")
    elif type_message == "03" and code == "02":
        print(f"\t\t Destination Protocol Unreachable")
        f.write(f"\t\t Destination Protocol Unreachable\n")
    elif type_message == "03" and code == "03":
        print(f"\t\t Destination Port Unreachable")
        f.write(f"\t\t Destination Port Unreachable\n")
    elif type_message == "03" and code == "04":
        print(f"\t\t fragmentation needed and DF set")
        f.write(f"\t\t fragmentation needed and DF set\n")
    elif type_message == "03" and code == "05":
        print(f"\t\t source route failed")
        f.write(f"\t\t source route failed\n")
    elif type_message == "03" and code == "06":
        print(f"\t\t Destination Network Unknown")
        f.write(f"\t\t Destination Network Unknown\n")
    elif type_message == "03" and code == "07":
        print(f"\t\t Destination Host Unknown")
        f.write(f"\t\t Destination Host Unknown\n")
    elif type_message == "04" and code == "00":
        print(f"\t\t Source Quench")
        f.write(f"\t\t Source Quench\n")
    elif type_message == "05" and code == "00":
        print(f"\t\t Redirect")
        f.write(f"\t\t Redirect\n")
        gateway_internet_address = get_ip(message[0:8])
        print(f"\t\t--> Gateway Internet Address : {gateway_internet_address}")
        f.write(f"\t\t--> Gateway Internet Address : {gateway_internet_address}\n")
    elif type_message == "08" and code == "00":
        id_echo = message[0:4]
        num_seq = message[4:8]
        print(f"\t\t Echo Request")
        f.write(f"\t\t Echo Request\n")
        print(f"\t\t--> Identifier = 0x{id_echo}")
        f.write(f"\t\t--> Identifier = 0x{id_echo}\n")
        print(f"\t\t--> Sequence Number = 0x{num_seq}")
        f.write(f"\t\t--> Sequence Number = 0x{num_seq}\n")
    elif (type_message == '0B' or type_message == '0b') and code == "00":
        print(f'\t\t Time Exceeded')
        f.write(f'\t\t Time Exceeded\n')
    elif (type_message == "0B" or type_message == "0b") and code == "01":
        print(f'\t\t Reassembly Time Exceeded ')
        f.write(f"\t\t Reassembly Time Exceeded\n")
    elif type_message == "0C" or type_message == "0c":
        print(f"\t\t Parameter Problem")
        f.write(f"\t\t Parameter Problem\n")
    elif type_message == "0D" or type_message == "0d":
        print(f"\t\t Timestamp")
        f.write(f"\t\t Timestamp\n")
    elif type_message == "0E" or type_message == "0e":
        id_echo = message[0:4]
        num_seq = message[4:8]
        or_ts = message[8:16]
        rc_ts = message[16:32]
        ts_ts = message[32:48]
        print(f"\t\t Timestamp Reply")
        f.write(f"\t\t Timestamp Reply\n")
        print(f"\t\t--> Identifier = 0x{id_echo}")
        f.write(f"\t\t--> Identifier = 0x{id_echo}\n")
        print(f"\t\t--> Sequence Number = 0x{num_seq}")
        f.write(f"\t\t--> Sequence Number = 0x{num_seq}\n")
        print(f"\t\t--> Originate Timestamp = 0x{or_ts}")
        f.write(f"\t\t--> Originate Timestamp = 0x{or_ts}\n")
        print(f"\t\t--> Receive Timestamp = 0x{rc_ts}")
        f.write(f"\t\t--> Receive Timestamp = 0x{rc_ts}\n")
        print(f"\t\t--> Transmit Timestamp  = 0x{ts_ts}")
        f.write(f"\t\t--> Transmit Timestamp  = 0x{ts_ts}\n")
    elif type_message == "0F" or type_message == "0f":
        print(f"\t\t Information Request")
        f.write(f"\t\t Information Request\n")
        id_echo = message[0:4]
        num_seq = message[4:8]
        print(f"\t\t--> Identifier = 0x{id_echo}")
        f.write(f"\t\t--> Identifier = 0x{id_echo}\n")
        print(f"\t\t--> Sequence Number = 0x{num_seq}")
        f.write(f"\t\t--> Sequence Number = 0x{num_seq}\n")
    elif type_message == "10":
        print(f"\t\t Information Reply")
        f.write(f"\t\t Information Reply\n")
        id_echo = message[0:4]
        num_seq = message[4:8]
        print(f"\t\t--> Identifier = 0x{id_echo}")
        f.write(f"\t\t--> Identifier = 0x{id_echo}\n")
        print(f"\t\t--> Sequence Number = 0x{num_seq}")
        f.write(f"\t\t--> Sequence Number = 0x{num_seq}\n")
    elif type_message == "11":
        print(f"\t\t Address Mask Request")
        f.write(f"\t\t Address Mask Request\n")
    else:
        print(f"\t\t Address Mask Reply")
        f.write(f"\t\t Address Mask Reply\n")


def analyse(tram, counter, f):
    displaying(tram, counter, f)
    ethernet_type = tram[24:28]
    pertinent_info = []
    if ethernet_type == '0806':
        # PERTINENT_Info = [ARP, address ip source, address ip destination]
        pertinent_info.append("ARP")
        hardware_type = tram[28:32]
        if hardware_type == "0001":
            hardware = "Ethernet"
        elif hardware_type == "0011":
            hardware = "HDLC"
        else:
            hardware = ""
        protocol_type = tram[32:36]
        if protocol_type == "0800":
            proto = "IPv4"
        else:
            proto = ""
        hlen = conversion_hex_to_decimal(tram[36:38])
        plen = conversion_hex_to_decimal(tram[38:40])
        operations = tram[40:44]
        if operations == "0001":
            op = "ARP Request"
        elif operations == "0002":
            op = "ARP Reply"
        else:
            op = ""
        source_hardware_address = get_mac(tram[44:56])
        source_protocol_address = get_ip(tram[56:64])
        pertinent_info.append(source_protocol_address)
        destination_hardware_address = get_mac(tram[64:76])
        destination_protocol_address = get_ip(tram[76:84])
        pertinent_info.append(destination_protocol_address)
        print("Ethernet : 42 bytes captured (336 bits)")
        f.write("Ethernet : 42 bytes captured (336 bits)\n")
        destination_mac_address = get_mac(tram[0:12])
        source_mac_address = get_mac(tram[12:24])
        print(f"\tDestination Mac Address : {destination_mac_address}")
        f.write(
            f"\tDestination Mac Address : {destination_mac_address}\n")
        print(f"\tSource Mac Address : {source_mac_address}")
        f.write(f"\tSource Mac Address : {source_mac_address}\n")
        print(f"\tType : Ox{ethernet_type}")
        f.write(f"\tType : Ox{ethernet_type}\n")

        print("ARP : ")
        f.write("ARP : \n")
        print(f"\tHardware Type : Ox{hardware_type} {hardware}")
        f.write(f"\tHardware Type : Ox{hardware_type} {hardware}\n")
        print(f"\tProtocol Type : Ox{protocol_type} {proto}")
        f.write(f"\tProtocol Type : Ox{protocol_type} {proto}\n")
        print(f"\tHLEN : {hlen}")
        f.write(f"\tHLEN : {hlen}\n")
        print(f"\tPLEN : {plen}")
        f.write(f"\tPLEN : {plen}\n")
        print(f"\tOperation : Ox{operations} {op}")
        f.write(f"\tOperation : Ox{operations} {op}\n")
        print(f"\tSource Hardware Address : {source_hardware_address}")
        f.write(
            f"\tSource Hardware Address : {source_hardware_address}\n")
        print(f"\tSource Protocol address : {source_protocol_address}")
        f.write(
            f"\tSource Protocol address : {source_protocol_address}\n")
        print(f"\tDestination Hardware Address : {destination_hardware_address}")
        f.write(
            f"\tDestination Hardware Address : {destination_hardware_address}\n")
        print(f"\tDestination Protocol address : {destination_protocol_address}")
        f.write(
            f"\tDestination Protocol address : {destination_protocol_address}\n")


    elif ethernet_type == '0800':

        version = tram[28:29]

        ihl = tram[29:30]
        tos = tram[30:32]
        total_length = tram[32:36]
        identifier = tram[36:40]
        fragment_msg = conversion_hex_to_binary(tram[40:44])
        reserved_bit = fragment_msg[0:1]
        dont_fragment = fragment_msg[1:2]
        more_fragment = fragment_msg[2:3]
        fragment_offset = fragment_msg[3:]
        ttl = tram[44:46]
        protocol = tram[46:48]

        if protocol == '01':
            protocol_name = "ICMP"
            pertinent_info.append("ICMP")
        elif protocol == '02':
            protocol_name = "IGMP"
            pertinent_info.append("IGMP")
        elif protocol == '06':
            protocol_name = "TCP"
            pertinent_info.append("TCP")
        elif protocol == '11':
            protocol_name = "UDP"
            pertinent_info.append("UDP")
        elif protocol == '29':
            protocol_name = "ENCAP"
            pertinent_info.append("ENCAP")
        elif protocol == '59':
            protocol_name = "OSPF"
            pertinent_info.append("OSPF")
        elif protocol == '84':
            protocol_name = "SCTP"
            pertinent_info.append("SCTP")
        else:
            protocol_name = ""
            pertinent_info.append("Unknown")

        header_checksome = tram[48:52]
        source_ip_address = get_ip(tram[52:60])
        pertinent_info.append(source_ip_address)
        destination_ip_address = get_ip(tram[60:68])
        pertinent_info.append(destination_ip_address)

        bytes_captured = conversion_hex_to_decimal(total_length) + 2 + 12
        bits_captured = bytes_captured * 4
        print(f"Ethernet : {bytes_captured} bytes captured ({bits_captured} bits)")
        f.write(
            f"Ethernet : {bytes_captured} bytes captured ({bits_captured} bits)\n")
        destination_mac_address = get_mac(tram[0:12])
        source_mac_address = get_mac(tram[12:24])
        print(f"\tDestination Mac Address : {destination_mac_address}")
        f.write(f"\tDestination Mac Address : {destination_mac_address}\n")
        print(f"\tSource Mac Address : {source_mac_address}")
        f.write(f"\tSource Mac Address : {source_mac_address}\n")
        print(f"\tType : Ox{ethernet_type}")
        f.write(f"\tType : Ox{ethernet_type}\n")

        # information Paquet Ip
        print("Entete IP : ")
        f.write("Entete IP : \n")

        print(f"\tVersion : {version}")
        f.write(f"\tVersion : {version}\n")
        print(f"\tIHL : Ox{ihl} <--> " + str(4 * hex_decimal[ihl]))
        f.write(f"\tIHL : Ox{ihl} <--> " + str(4 * hex_decimal[ihl]) + "\n")

        # some IHL controls :
        ihl_decimal = hex_decimal[ihl] * 4
        if ihl_decimal == 20:
            analyse_pointer = 68

        else:
            ip_option_length = ihl_decimal - 20
            analyse_pointer = 68 + 2 * ip_option_length

        print(f"\tType of Service : " + str(conversion_hex_to_decimal(tos)))
        f.write(f"\tType of Service : " + str(conversion_hex_to_decimal(tos)) + "\n")
        print(f"\tTotal Length : Ox{total_length} (" + str(conversion_hex_to_decimal(total_length)) + ")")
        f.write(f"\tTotal Length : Ox{total_length} (" + str(conversion_hex_to_decimal(total_length)) + ")\n")
        print(f"\tIdentifier : Ox{identifier} (" + str(conversion_hex_to_decimal(identifier)) + ")")
        f.write(f"\tIdentifier : Ox{identifier} (" + str(conversion_hex_to_decimal(identifier)) + ")\n")
        print(f"\t\tReserved bite : {reserved_bit}")
        f.write(f"\t\tReserved bite : {reserved_bit}\n")
        print(f"\t\tDont Fragment : {dont_fragment}")
        f.write(f"\t\tDont Fragment : {dont_fragment}\n")
        print(f"\t\tMore Fragment : {more_fragment}")
        f.write(f"\t\tMore Fragment : {more_fragment}\n")
        print(f"\t\tFragment Offset : {fragment_offset} (" + str(conversion_binary_to_decimal(fragment_offset)) + ")")
        f.write(f"\t\tFragment Offset : {fragment_offset} (" + str(
            conversion_binary_to_decimal(fragment_offset)) + ")\n")
        print(f"\tTTL : Ox{ttl} (" + str(conversion_hex_to_decimal(ttl)) + ")")
        f.write(f"\tTTL : Ox{ttl} (" + str(conversion_hex_to_decimal(ttl)) + ")\n")
        print(f"\tProtocol {protocol_name}: Ox{protocol} (" + str(conversion_hex_to_decimal(protocol)) + ")")
        f.write(
            f"\tProtocol {protocol_name}: Ox{protocol} (" + str(conversion_hex_to_decimal(protocol)) + ")\n")
        print(f"\tHeader Checksome : Ox{header_checksome} (" + str(conversion_hex_to_decimal(header_checksome)) + ")")
        f.write(f"\tHeader Checksome : Ox{header_checksome} (" + str(
            conversion_hex_to_decimal(header_checksome)) + ")\n")
        print(f"\tSource IP Address : {source_ip_address}")
        f.write(f"\tSource IP Address : {source_ip_address}\n")
        print(f"\tDestination ID Address : {destination_ip_address}")
        f.write(
            f"\tDestination ID Address : {destination_ip_address}\n")

        if ihl_decimal > 20:
            print("\tOptions IP :")
            f.write("\tOptions IP :\n")
            ip_option_length = ihl_decimal - 20
            analyse_ip_options(tram[68:68 + 2 * ip_option_length], 1, f)
            print()
            f.write("\n")
        else:

            print("\tCe paquet IP ne contient pas d'option!")
            f.write("\tCe paquet IP ne contient pas d'option!\n")

        if protocol == '01':
            # PERTINENT_Info = [ICMP, address ip source, address ip destination]
            print("Protocol ICMP : ")
            f.write("Protocol ICMP : \n")
            type_icmp = tram[analyse_pointer:analyse_pointer + 2]
            code_icmp = tram[analyse_pointer + 2:analyse_pointer + 4]
            checksome_icmp = tram[analyse_pointer + 4:analyse_pointer + 8]
            print(f"\tType : Ox{type_icmp} (" + str(conversion_hex_to_decimal(type_icmp)) + ")")
            f.write(
                f"\tType : Ox{type_icmp} (" + str(conversion_hex_to_decimal(type_icmp)) + ")\n")
            print(f"\tCode : Ox{code_icmp} (" + str(conversion_hex_to_decimal(code_icmp)) + ")")
            f.write(f"\tCode : Ox{code_icmp} (" + str(conversion_hex_to_decimal(code_icmp)) + ")\n")
            print(f"\tChecksome : Ox{checksome_icmp}")
            f.write(f"\tChecksome : Ox{checksome_icmp}\n")
            analyse_icmp(type_icmp, code_icmp, tram[analyse_pointer + 8:], f)


        if protocol == '02':
            # PERTINENT_Info = [IGMP, address ip source, address ip destination]
            print("Protocol IGMP : ")
            f.write("Protocol IGMP : \n")
            type_igmp = tram[analyse_pointer:analyse_pointer + 2]
            if type_igmp == '11':
                type_igmp_msg = "Membership Query"
            elif type_igmp == '12':
                type_igmp_msg = "IGMPv1 Membership Report"
            elif type_igmp == '16':
                type_igmp_msg = "IGMPv2 Membership Report"
            elif type_igmp == '22':
                type_igmp_msg = "IGMPv3 Membership Report"
            else:
                type_igmp_msg = "Leave Group"

            max_rep_igmp = tram[analyse_pointer + 2:analyse_pointer + 4]
            checksome_igmp = tram[analyse_pointer + 4:analyse_pointer + 8]
            multi_cas_adr = get_ip(
                tram[analyse_pointer + 8:analyse_pointer + 16])
            print(f"\tType : {type_igmp_msg} Ox{type_igmp}")
            f.write(f"\tType : {type_igmp_msg} Ox{type_igmp}\n")
            print(f"\tMax Resp Time : Ox{max_rep_igmp} (" + str(conversion_hex_to_decimal(max_rep_igmp)) + ")")
            f.write(f"\tMax Resp Time : Ox{max_rep_igmp} (" + str(conversion_hex_to_decimal(max_rep_igmp)) + ")\n")
            print(f"\tChecksum : Ox{checksome_igmp}")
            f.write(f"\tChecksum : Ox{checksome_igmp}\n")
            print(f"\tMulticast Address  : {multi_cas_adr}")
            f.write(f"\tMulticast Address  : {multi_cas_adr}\n")


        if protocol == '11':
            # PERTINENT_Info = [UDP, address ip source, address ip destination, source port, destination port]
            print("Protocol UDP : ")
            f.write("Protocol UDP : \n")
            source_port_number = conversion_hex_to_decimal(tram[analyse_pointer:analyse_pointer + 4])
            pertinent_info.append(source_port_number)
            destination_port_number = conversion_hex_to_decimal(tram[analyse_pointer + 4:analyse_pointer + 8])
            pertinent_info.append(destination_port_number)
            udp_length = conversion_hex_to_decimal(tram[analyse_pointer + 8:analyse_pointer + 12])
            udp_checksome = tram[analyse_pointer + 12:analyse_pointer + 16]
            print(f"\tSource Port Number : {source_port_number}")
            f.write(f"\tSource Port Number : {source_port_number}\n")
            print(f"\tDestination Port Number : {destination_port_number}")
            f.write(f"\tDestination Port Number : {destination_port_number}\n")
            print(f"\tLength : {udp_length}")
            f.write(f"\tLength : {udp_length}\n")
            print(f"\tChecksome : 0x{udp_checksome}")
            f.write(f"\tChecksome : 0x{udp_checksome}\n")

        if protocol == '06':

            # PERTINENT_Info = [TCP, address ip source, address ip destination, source port, destination port, message]
            # information Segment TCP
            print("Entete TCP : ")
            f.write("Entete TCP : \n")

            source_port_number = conversion_hex_to_decimal(tram[analyse_pointer:analyse_pointer + 4])
            pertinent_info.append(source_port_number)
            destination_port_number = conversion_hex_to_decimal(tram[analyse_pointer + 4:analyse_pointer + 8])
            pertinent_info.append(destination_port_number)
            sequence_number = conversion_hex_to_decimal(tram[analyse_pointer + 8:analyse_pointer + 16])
            pertinent_message = ""
            acknowledgment_number = conversion_hex_to_decimal(tram[analyse_pointer + 16:analyse_pointer + 24])

            thl = tram[analyse_pointer + 24:analyse_pointer + 25]
            other = conversion_hex_to_binary(tram[analyse_pointer + 25:analyse_pointer + 28])
            reserved = other[0:6]
            urg = other[6:7]
            ack = other[7:8]
            psh = other[8:9]
            rst = other[9:10]
            syn = other[10:11]
            fin = other[11:12]
            pertinent_message += "["

            if urg == '1':
                pertinent_message += "Urg "
            if ack == '1':
                pertinent_message += "Ack "
            if psh == '1':
                pertinent_message += "Psh "
            if rst == '1':
                pertinent_message += "Rst "
            if syn == '1':
                pertinent_message += "Syn "
            if fin == '1':
                pertinent_message += "Fin "

            pertinent_message += "] "
            window = tram[analyse_pointer + 28:analyse_pointer + 32]
            checksome = tram[analyse_pointer + 32:analyse_pointer + 36]
            urgent_pointer = tram[analyse_pointer + 36:analyse_pointer + 40]
            print(f"\tSource Port Number : {source_port_number}")
            f.write(f"\tSource Port Number : {source_port_number}\n")
            print(f"\tDestination Port Number : {destination_port_number}")
            f.write(
                f"\tDestination Port Number : {destination_port_number}\n")
            print(f"\tSequence Number : {sequence_number}")
            f.write(f"\tSequence Number : {sequence_number}\n")
            print(f"\tAcknowledgment Number : {acknowledgment_number}")
            f.write(
                f"\tAcknowledgment Number : {acknowledgment_number}\n")
            print(f"\tTHL : Ox{thl}")
            f.write(f"\tTHL : Ox{thl}\n")
            print(f"\tReserved : {reserved}")
            f.write(f"\tReserved : {reserved}\n")
            print("\tFlags : ")
            f.write("\tFlags : \n")
            print(f"\t\tURG : {urg}")
            f.write(f"\t\tURG : {urg}\n")
            print(f"\t\tACK : {ack}")
            f.write(f"\t\tACK : {ack}\n")
            print(f"\t\tPSH : {psh}")
            f.write(f"\t\tPSH : {psh}\n")
            print(f"\t\tRST : {rst}")
            f.write(f"\t\tRST : {rst}\n")
            print(f"\t\tSYN : {syn}")
            f.write(f"\t\tSYN : {syn}\n")
            print(f"\t\tFIN : {fin}")
            f.write(f"\t\tFIN : {fin}\n")
            print(f"\tWindow : Ox{window} <--> " +
                  str(conversion_hex_to_decimal(window)))
            f.write(f"\tWindow : Ox{window} <--> " +
                    str(conversion_hex_to_decimal(window)) + "\n")
            print(f"\tChecksum : Ox{checksome}")
            f.write(f"\tChecksum : Ox{checksome}\n")
            print(f"\tUrgent Pointer : Ox{urgent_pointer}")
            f.write(f"\tUrgent Pointer : Ox{urgent_pointer}\n")

            pertinent_message += f"Win = 0x{window} "
            pertinent_message += f"Seq = {sequence_number} "
            if ack == '1':
                pertinent_message += f"Ack = {acknowledgment_number} "

            # some controls :
            thl_decimal = hex_decimal[thl] * 4
            if thl_decimal == 20:
                print("\tCe Segment TCP ne contient pas d'option!")
                f.write("\tCe Segment TCP ne contient pas d'option!\n")
                tcp_pointer = analyse_pointer + 40
            else:
                print("\tCe segment TCP contient des options!")
                f.write("\tCe segment TCP contient des options!\n")

                tcp_option_length = thl_decimal - 20
                tcp_pointer = analyse_pointer + 40 + 2 * tcp_option_length
                analyse_tcp_options(tram[analyse_pointer + 40:analyse_pointer + 2 * tcp_option_length], 1, f)

            if len(tram[tcp_pointer:]) > 0:
                if source_port_number == 80 or destination_port_number == 80:
                    pertinent_message += " HTTP"
                    http_message = get_http_message(tram[tcp_pointer:])
                    print("\tLe message HTTP est :")
                    f.write("\tLe message HTTP est :\n\n")
                    print(http_message)
                    f.write(http_message)
                    f.write("\n")

            pertinent_info.append(pertinent_message)

    # fin analyse
    print("\n")
    return pertinent_info


def is_well_formed(filepath):
    with open(filepath, 'r') as filee:
        last_offset = 0
        while True:
            # Get next line from file
            line_i = filee.readline()

            # if line is empty
            # end of file is reached
            if not line_i:
                return True

            # offset of the line is the first 4 characters
            try:
                offset_line = int(line_i[0:4], 16)
            except ValueError:
                return False
            # the offset needs to be a multiple of 16 else error
            if offset_line % 16 != 0:
                return False
            if offset_line == 0:
                last_offset = 0
            elif offset_line - 16 != last_offset:
                return False
            else:
                last_offset = offset_line
                # we will get now the actual message in the line
                message: str = line_i[7:54].strip()
                # we will check if evey hex character is valid
                j = 0
                while j < len(message):
                    if message[j] not in hex_digits or message[j + 1] not in hex_digits:
                        return False
                    j += 3
