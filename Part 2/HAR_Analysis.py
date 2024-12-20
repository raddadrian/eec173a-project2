import os
import json

# function to analyze HAR files
# process a HAR file to extract third-party cookies and request details.
def process_har_file(filename, cookie_store, request_counter, file_dir):
    # read the HAR file
    try:
        with open(os.path.join(file_dir, filename), 'r', encoding='utf-8') as file:
            har_data = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        print(f'Failed to load HAR file: {filename}')
        return cookie_store, request_counter

    # extract entries
    entries = har_data.get('log', {}).get('entries', [])
    req_cookie_list, res_cookie_list, req_url_list = [], [], []

    # process each entry
    for entry in entries:
        # request cookies
        request = entry.get('request', {})
        req_cookies = request.get('cookies', [])
        req_url = request.get('url', "")

        for cookie in req_cookies:

            if req_url:
                req_cookie_list.append((req_url, cookie.get('name')))
                req_url_list.append(req_url)

        # response cookies
        response = entry.get('response', {})
        res_cookies = response.get('cookies', [])

        for cookie in res_cookies:

            domain = cookie.get('domain')

            if domain:
                res_cookie_list.append((domain, cookie.get('name')))

    # combine request and response cookies
    combined_cookies = req_cookie_list + res_cookie_list

    # extract domain name
    common_domains = ['.com', '.net', '.org', '.edu', '.co', '.ru', '.uk', '.jp', '.io', '.it', '.br', '.cn']

    underscore_pos = filename.find("_")
    domain_end = next((filename.find(dom) for dom in common_domains if dom in filename), filename.rfind('.'))
    site_name = filename[underscore_pos + 1:domain_end]

    # add dot for small site names
    if len(site_name) < 6:
        site_name += '.'

    # count third-party requests
    request_counter[site_name] = sum(1 for url in req_url_list if site_name not in url)
    print(f"Third-party requests for {site_name}: {request_counter[site_name]}")

    # update cookie counts
    for domain, name in combined_cookies:

        if site_name not in domain:
            cookie_store.setdefault(domain, {}).setdefault(name, 0)
            cookie_store[domain][name] += 1

    return cookie_store, request_counter


if __name__ == "__main__":
    DIRECTORY = '/Users/adrianrivera/Desktop/EEC 173A (ECS 152)/Project 2/HAR_Files/'
    har_files = os.listdir(DIRECTORY)

    cookie_store = {}
    request_counter = {}

    for har_file in har_files:
        cookie_store, request_counter = process_har_file(har_file, cookie_store, request_counter, DIRECTORY)

    # Top 10 cookies summary
    top_cookies = sorted(((domain, name, count) for domain, cookies in cookie_store.items() for name, count in cookies.items()), key = lambda x: x[2], reverse = True)[:10]

    print("\nTop 10 Cookies: ")
    for cookie in top_cookies:
        print(cookie)

    # Top 10 third-party domains summary
    top_domains = sorted(request_counter.items(), key = lambda x: x[1], reverse = True)[:10]

    print('\nTop 10 Domains:')
    for domain, count in top_domains:
        print(f"{domain}: {count}")
