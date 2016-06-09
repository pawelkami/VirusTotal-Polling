import json
import urllib2
import argparse
import base64
import hashlib

server_addr="http://localhost:24563"

def sendRequest(data):
    req = urllib2.Request(server_addr)
    req.add_header("Content-Type", "application/json")

    return urllib2.urlopen(req, json.dumps(data))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script facilitating communication with VirusTotalPolling server")

    parser.add_argument('-i', '--interval', action='store', dest='interval', help='Interval of rescanning files')
    parser.add_argument('-n', action='store', dest='number_of_cycles', help='Number of rescan cycles to do')
    parser.add_argument('-url', action='store', dest='server_url', help='Server address')

    input_type = parser.add_mutually_exclusive_group(required=True)
    input_type.add_argument('-f', action='store', dest='file_path', help='Path of file')
    input_type.add_argument('-sha', action='store', dest='sha256', help='SHA256 of file')

    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('-r', '--rescan', action='store_true', help='Rescan sample')
    action.add_argument('-s', '--send', action='store_true', help='Send sample')
    action.add_argument('-g', '--get_results', action='store_true', help='Retrieves results')

    args = parser.parse_args()

    if args.rescan and args.sha256:
        print('Cannot scan sample with only hash given')
        exit()

    if args.get_results and (args.interval or args.number_of_cycles):
        print('Cannot get results in cycles')
        exit()

    type = "rescan"
    data = {}
    file_data = None
    if args.file_path is not None:
        if args.send:
            type = "send"
            data['filename'] = args.file_path[args.file_path.rfind('/') + 1:]
            file_data = open(args.file_path, 'rb').read()
            data['file'] = base64.b64encode(file_data)
        else:
            # Calculate sha256 of file
            BLOCKSIZE = 65536
            hasher = hashlib.sha256()
            with open(args.file_path, 'rb') as file:
                buf = file.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = file.read(BLOCKSIZE)
            data['sha256'] = hasher.hexdigest()

            if args.rescan:
                type = "rescan"
            else:
                type = "get_results"
    else:
        data['sha256'] = args.sha256
        if args.rescan:
            type = "rescan"
        else:
            type = "get_results"

    data['type'] = type

    cycling = "no"
    if args.interval != None and args.number_of_cycles != None:
        cycling = "yes"
        data['interval'] = args.interval
        data['numberOfCycles'] = args.number_of_cycles
    data['cycling'] = cycling


    if args.server_url != None:
        server_addr = args.server_url

    response = sendRequest(data)

    if args.get_results:
        print(response)
