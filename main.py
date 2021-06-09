import os
import sys
import datetime
import hashlib
import requests
import argparse
import json
import logging
import base64
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
AUTH_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiIyOGQ2ZTNkNS05ZTA2LTQ2YzItOWFlNC0wOTM1NGExNThlMzYiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNjIzMTM2OTc5LCJ1aWQiOiJpbm1hdGUxMzM3QHByb3Rvbm1haWwuY29tIiwicGwiOiIiLCJldCI6MTY1NDY3Mjk3OX0.lAW2r0YcXquaTmRGzRXA4aXc7fUoROB5zb1G29NgfM-XTPEa-tajwQ052zeIBQ5hyGsneE5BURZLEhDHGrp7bi2TtxsW3ntSLSEXkE-L2K3cvmtE-zQk4jIRt_pnXYfQ2egcv1YGw9FpnlJ2pFBTrYuCONqgC9D51Ntgb5Z2YmtFnkER7zrbe-ws742rrgYmYzev3KwGXQFYCL3xFx4zYWOyYrglvOQ2Agn6zufpqgp-MjpY4O-s1bH_w3ay8fx_Oq2Xop9pzlJC7n0Jv8xLC51tYabc2KtMOmIw_ctsXzI8CXiFMidSaxzRo0lCDZEBrGxIawb01IMXwq6WPrep1LykSLI6nR-WtE28tK4qVWEEFpqHE92MfkbJKrcQS9UsAZJ4or-4oNYfOmVtwdRLo1n4Kg8logyFnqov5cUqVW24OiGtp8qUVsUk_U_SGcxu-g77HJJepER85h6UZNuqxcPjA2kViw5rnIo6b1N-1heYzdoopyZ8f5evVF312FN_zBvqr6KgrZHS7vyK7AyO0xTg1O3H8bobR1q_zTeBraK2YM3zFLi4USIn4DYUL0K1lmkJ3_Gln5eYLPSBhqhF8NTxcZt8F_RT69yKQN5z2hRyoZbv-EaBzC4ehGGauPRJz-pVWf9OxDM3GBb9qarUcnu9fWHAOBV_H8kL2_hWRkk"
BASE_URL = "https://api.eu.xdr.trendmicro.com/beta/xdr/sandbox/"
HEADERS = {
  'Authorization': 'Bearer {}'.format(AUTH_TOKEN)
}
HEADERS_B = {
    'Content-Type': 'application/pdf',
    'Authorization': 'Bearer {}'.format(AUTH_TOKEN)
}
PAYLOAD = {}

def encode(string):
    ret = base64.b64encode(string.encode("ascii"))
    return ret
def file_submit(fname, documentPassword, archivePassword):
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
    logger.info("{} : {}".format(datetime.datetime.now(),json.dumps(ret, indent=4, sort_keys=False)))

def check_state(taskID):

    url = "{}tasks/{}".format(BASE_URL, taskID)
    response = requests.request("GET", url, headers=HEADERS, data=PAYLOAD)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(),json.dumps(ret, indent=4, sort_keys=False)))

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
    url = "{}reports/{}?type=suspiciousObject".format(BASE_URL, reportId)
    response = requests.request("GET", url, headers=HEADERS_B, data=PAYLOAD)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(),json.dumps(ret, indent=4, sort_keys=False)))

def get_quota():
    url = "{}quota".format(BASE_URL)
    response = requests.request("GET", url, headers=HEADERS_B, data=PAYLOAD)
    ret = json.loads(response.text)
    print(json.dumps(ret, indent=4, sort_keys=False))
    logger.info("{} : {}".format(datetime.datetime.now(),json.dumps(ret, indent=4, sort_keys=False)))


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

