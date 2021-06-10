import os
import sys
import datetime
import time
import hashlib
import requests
import argparse
import json
import logging
import base64
from termcolor import colored
BANNER = """
#######################################################
#                                                     #
#                 Vision One submit.                  #
#           V1 Sandbox API tool. version 1.0          #
#                                                     #
#######################################################

"""



TODAY = datetime.datetime.today().strftime('%Y-%m-%d')
LOG_FILE = "{}.log".format(TODAY)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
AUTH_TOKEN = ""
VT_API_KEY = ""
HYBRID_ANA_KEY = ""
DELAY = 10
BASE_URL = "https://api.eu.xdr.trendmicro.com/beta/xdr/sandbox/"
HEADERS = {
    'Authorization': 'Bearer {}'.format(AUTH_TOKEN)
}
HEADERS_B = {
    'Content-Type': 'application/pdf',
    'Authorization': 'Bearer {}'.format(AUTH_TOKEN)
}
PAYLOAD = {}

def hybrid_ana(search):
    url = "https://hybrid-analysis.com/api/v2/search/hash"

    payload = {'hash': search}
    files = [

    ]
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': HYBRID_ANA_KEY
    }

    response = requests.request("POST", url, headers=headers, data=payload, files=files)
    ret = response.json()
    logger.info("{} : message: [{}].".format(datetime.datetime.now(), response.json()))
    if ret:
        ha = ({'submit_name': ret[0]['submit_name'],
               'ssdeep': ret[0]['ssdeep'],
               'imphash': ret[0]['imphash'],
               'analysis_start_time': ret[0]['analysis_start_time'],
               'av_detect': ret[0]['av_detect'],
               'threat_score': ret[0]['threat_score'],
               'verdict': ret[0]['verdict'],
               })
        return ha
    else:
        return {'message': 'Hash not in Hybrid Analysis.'}

def simple_vt_report(search):
    vt_report = {}
    vt = {}

    vt_report = virustotal(search)
    try:
        if vt_report["response_code"] == 1:
            vt = ({"scan_date": vt_report["scan_date"],
                "positives": vt_report["positives"],
                "total": vt_report["total"],
                "sha256": vt_report["sha256"]
                })
        else:
            vt = ({"message": "File hash not in VT."})
    except:
        logger.error("{} : {}".format(datetime.datetime.now(), vt_report))
        vt = vt_report
    return vt


def virustotal(tosearch):
    result = []

    if VT_API_KEY:
        params = {'apikey': VT_API_KEY, 'resource': tosearch}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  Retro-Hunter"
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        logger.info("{} : message: [{}].".format(datetime.datetime.now(), response.json()))
        return response.json()
    else:
        logger.error("{} : message: Please check your Virustotal API key.".format(datetime.datetime.now()))
        return {}


def encode(string):
    ret = base64.b64encode(string.encode("ascii"))
    return ret


def file_submit(fname, documentPassword, archivePassword):
    PAYLOAD = {}
    if documentPassword:
        PAYLOAD = {'documentPassword': encode(documentPassword)}
    if archivePassword:
        PAYLOAD = {'archivePassword': encode(archivePassword)}
    print("Now submitting file : {} to V1 Cloud Sandbox!".format(fname))
    url = "{}file".format(BASE_URL)
    files = [
        ('file',
         (os.path.basename(fname), open(fname, 'rb'), 'application/octet-stream'))
    ]
    response = requests.request("POST", url, headers=HEADERS, data=PAYLOAD, files=files)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(), json.dumps(ret, indent=4, sort_keys=False)))


def check_state(taskID):
    url = "{}tasks/{}".format(BASE_URL, taskID)
    response = requests.request("GET", url, headers=HEADERS, data=PAYLOAD)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(), json.dumps(ret, indent=4, sort_keys=False)))


def get_vaReport(reportId):
    rname = "VAReport-{}.pdf".format(reportId)
    url = "{}reports/{}?type=vaReport".format(BASE_URL, reportId)
    response = requests.request("GET", url, headers=HEADERS_B, data=PAYLOAD)
    f = open(rname, "wb")
    f.write(response.content)
    logger.info("{} : {} downloaded!".format(datetime.datetime.now(), rname))
    print("{} downloaded!".format(rname))


def get_invP(reportId):
    rname = "investigationPackage-{}.zip".format(reportId)
    url = "{}reports/{}?type=investigationPackage".format(BASE_URL, reportId)
    response = requests.request("GET", url, headers=HEADERS_B, data=PAYLOAD)
    f = open(rname, "wb")
    f.write(response.content)
    logger.info("{} : {} downloaded!".format(datetime.datetime.now(), rname))
    print("{} downloaded!".format(rname))


def get_so(reportId):
    dot = ""
    url = "{}reports/{}?type=suspiciousObject".format(BASE_URL, reportId)
    response = requests.request("GET", url, headers=HEADERS_B, data=PAYLOAD)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(), json.dumps(ret, indent=4, sort_keys=False)))
    print(colored('// Checking Suspicious objects against Threat intel.', attrs=['bold']))
    if not VT_API_KEY:
        print(colored("{'message': 'ERROR!', 'reason': 'No Virustotal API key found.'}", 'red'))
        sys.exit(0)
    try:
        for _s in ret['data']:
            if _s['type'] == "sha1":
                dot = dot + "."
                print("Checking File hash", colored('[{}]'.format(_s['value']), 'yellow'), "against Virustotal. Hang on{}".format(dot))
                time.sleep(DELAY)
                try:
                    print(colored('{}'.format(simple_vt_report(_s['value'])), 'white'))
                except Exception as e:
                    print(colored("{'message': 'Did not get any result from VT.', 'reason': 'Depending on the no. of requests, we might have hit a timeout.', 'logfile': "+LOG_FILE+"}", 'red'))
                    logger.error("{} : {}".format(datetime.datetime.now(), e))
                print("Checking File hash", colored('[{}]'.format(_s['value']), 'yellow'),
                  "against Hybrid Analysis. Hang on{}".format(dot))
                try:
                    print(colored('{}'.format(hybrid_ana(_s['value'])), 'white'))
                except:
                    print(colored(
                        "{'message': 'Did not get any result from Hybrid Analysis.', 'reason': 'Check logs.', 'logfile': " + LOG_FILE + "}",
                        'red'))
                    logger.error("{} : {}".format(datetime.datetime.now(), e))

    except Exception as ex:
        logger.error("{} : {}".format(datetime.datetime.now(), ex))
        pass


def get_quota():
    url = "{}quota".format(BASE_URL)
    response = requests.request("GET", url, headers=HEADERS_B, data=PAYLOAD)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(), json.dumps(ret, indent=4, sort_keys=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=False,
                        help='Specify the file path (e.g. /full/path/to/file). Optional. --documentPassword, --archivePassword')
    parser.add_argument('--documentPassword', type=str, required=False,
                        help='Indicate the password for decrypting the submitted document-type1 sample')
    parser.add_argument('--archivePassword', type=str, required=False,
                        help='Indicate the password for decrypting the submitted archive-type1 sample')
    parser.add_argument('-t', '--task', type=str, required=False,
                        help='Takes in the taskID and returns status of the submitted file')
    parser.add_argument('-r', '--report', type=str, required=False,
                        help='Takes in the reportId and returns V1 Sandbox Report as PDF')
    parser.add_argument('-i', '--investigationPackage', type=str, required=False,
                        help='Takes in the reportId and returns V1 Sandbox investigation package.')
    parser.add_argument('-s', '--suspiciousObject', type=str, required=False,
                        help='Takes in the reportId and returns V1 Sandbox Suspicious objects.')
    parser.add_argument('-q', '--quota', action="store_true",
                        help='Check your daily submission quota.')
    args, commands = parser.parse_known_args()

    if commands:
        logger.warning('Unrecognized args: {}'.format(commands))
        sys.exit(1)

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(1)

    if args.file:
        print(BANNER)
        file_submit(args.file, args.documentPassword, args.archivePassword)

    if args.task:
        check_state(args.task)

    if args.report:
        get_vaReport(args.report)

    if args.investigationPackage:
        get_invP(args.investigationPackage)

    if args.suspiciousObject:
        get_so(args.suspiciousObject)

    if args.quota:
        get_quota()
