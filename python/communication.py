import json
import urllib2
import argparse
import httplib

server_addr="localhost:24563"

def sendRequest(data):
    #req = urllib2.Request(server_addr)
    #req.add_header("Content-Type", "application/json")

    #response = urllib2.urlopen(req, json.dumps(data))
    #print response
    conn = httplib.HTTPConnection(server_addr)
    conn.putrequest("POST", "/")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(data)))
    conn.endheaders()
    conn.send(json.dumps(data))
    errcode, errmsg, headers = conn.getreply()

    print conn.file.read()

def sendFile(file_data, data):
    headers = {"Content-Type" : "application/octet-stream", "Content-Length" : str(len(file_data)) }
    # pierwszy request
    conn = httplib.HTTPConnection(server_addr)
    conn.request("POST", "/", file_data, headers)
    r1 = conn.getresponse()
    
    # drugi request
    headers = { "Content-Type": "application/json", "Content-Length": str(len(data))}
    conn.request("POST", "/", json.dumps(data), headers)
    r2 = conn.getresponse()

    
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', action='store', dest='file_path', help='Path of file to send')
    parser.add_argument('-sha', action='store', dest='sha256', help='SHA256 of file to rescan')
    parser.add_argument('-i', '--interval', action='store', dest='interval', help='Interval of rescanning files')
    parser.add_argument('-n', action='store', dest='number_of_cycles', help='Number of rescan cycles to do')
    parser.add_argument('-url', action='store', dest='server_url', help='Server address')

    results = parser.parse_args()
    type = "rescan"
    data = {}
    file_data = None
    if results.file_path != None:
        type = "send"
        data['filename'] = results.file_path[results.file_path.rfind('/')+1:]
        file_data = open(results.file_path, 'rb').read()
    elif results.sha256 != None:
        type = "rescan"
        data['sha256'] = results.sha256

    data['type'] = type

    cycling = "no"
    if results.interval != None and results.number_of_cycles != None:
        cycling = "yes"
        data['interval'] = results.interval
        data['numberOfCycles'] = results.number_of_cycles
    data['cycling'] = cycling

    if results.server_url != None:
        server_addr = results.server_url


    if file_data != None:
        sendFile(file_data, data)
    #sendRequest(data)
