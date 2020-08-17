from multiprocessing import Process
import requests
import re
from pydnsbl import DNSBLDomainChecker
from pydnsbl.providers import Provider
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser

PROVIDERS = [Provider('multi.uribl.com')]
CHECKER = DNSBLDomainChecker(providers=PROVIDERS)

GOOGLE_API_KEY = "your google api key"
GOOGLE_CLIENT_ID = "your google clientId"
GOOGLE_CLENT_VERSION = "your google clientVersion"
email_file = "path to yout .eml file"


def expand_url(session, url):
    resp = session.head(url, allow_redirects=True)
    return resp.url


def check_against_google_safe_browsing(extended_url):
    request_body = {
        "client": {
            "clientId": GOOGLE_CLIENT_ID,
            "clientVersion": GOOGLE_CLENT_VERSION
        },
        "threatInfo": {
            "threatTypes": [
                "THREAT_TYPE_UNSPECIFIED",
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["LINUX"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": extended_url}
            ]
        }
    }
    try:
        request = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            json=request_body
        )
        if bool(request.json()):
            return "Yes"
        return "No"
    except Exception:
        return "Connection error"


def check_against_multi_uribl_com(extended_url):
    domain = urlparse(extended_url).netloc
    try:
        if CHECKER.check(domain).blacklisted:
            return "Yes"
        return "No"
    except Exception:
        return "Connection error"


def check_url(session, url):
    try:
        extended_url = expand_url(session, url)
        google_safe_browsing_response = check_against_google_safe_browsing(extended_url)
        multi_uribl_com_response = check_against_multi_uribl_com(extended_url)
        print(f"{extended_url}\n"
              f"        Listed on Google Safe Browsing: {google_safe_browsing_response}\n"
              f"        Listed on multi.uribl.com: {multi_uribl_com_response}")
    except Exception:
        print(f"{url} url error")


if __name__ == "__main__":
    session = requests.Session()
    regex = r'http[s]*://[bit.ly|tinyurl.com|goo.gl|t.co]+/[a-zA-Z0-9_.+-/#~]*'

    with open(email_file, 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)
        mail_content = msg.get_payload()[1].get_payload()

    url_list = re.findall(regex, mail_content)

    processes = [Process(target=check_url, args=(session, url)) for url in url_list]

    for p in processes:
        p.start()

    for p in processes:
        p.join()

