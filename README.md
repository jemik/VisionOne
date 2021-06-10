# VisionOne
### **Update.**

Virustotal file look up added in Get Suspicious Objects.
Hybrid Analysis file look up added in Get Suspicious Objects.

### **Install instructions.**
pip install -r requirements.txt \
Go get Authentication token from Vision One \
Paste into main.py **AUTH_TOKEN = "YOUR TOKEN"** \
**Optional**: Virustotal lookup. Add your API key to  **VT_API_KEY = "YOUR VT API Key"** \
**Optional**: Hybrid Analysis lookup. Add your API key to  **HYBRID_ANA_KEY = "YOUR VT API Key"** \
Change **BASE_URL** if needed. 
### **Usage.**

`usage: main.py [-h] [-f FILE] [--documentPassword DOCUMENTPASSWORD] [--archivePassword ARCHIVEPASSWORD] [-t TASK] [-r REPORT] [-i INVESTIGATIONPACKAGE] [-s SUSPICIOUSOBJECT]
`

Submit file to Vision One Cloud Sandbox \
`python main.py -f <Path to file>` \
`python main.py -f <Path to file> --documentPassword PASSWORD` \
`python main.py -f <Path to file> --archivePassword PASSWORD` 


Check processing status of the submitted file. \
`python main.py -t <taskId> `

Download Sandbox report. \
`python main.py -r <reportID>`

Download Investigation Package report. \
`python main.py -i <reportID>`

GET Suspicious Objects. \
`python main.py -s <reportID>`

Retrieves the maximum number of files that you can submit to the sandbox per day (Note. Objects with a "Not analyzed" risk level do not count toward this quota.). \
`python main.py -q`

Author : Jesper Mikkelsen.
