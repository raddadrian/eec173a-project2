from browsermobproxy import Server
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
import csv
import json

# create a browsermob server instance
server = Server("browsermob-proxy/bin/browsermob-proxy")
server.start()
proxy = server.create_proxy(params=dict(trustAllServers=True))

# create a new chromedriver instance
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument(f"--proxy-server={proxy.proxy}")
chrome_options.add_argument('--ignore-certificate-errors')

# these additional chrome options improve the performance of the crawling process
chrome_options.add_argument('--disable-accelerated-2d-canvas')
chrome_options.add_argument('--disable-software-rasterizer')
chrome_options.add_argument('--disable-popup-blocking')
chrome_options.add_argument('--disable-web-security')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--disable-blink-features=AutomationControlled')
chrome_options.add_argument('--disable-logging')
chrome_options.add_argument('--disable-extensions')
chrome_options.add_argument('--disable-third-party-cookies=false')
chrome_options.add_argument('--hide-scrollbars')
chrome_options.add_argument('--headless')
chrome_options.add_argument('--mute-audio')
chrome_options.add_argument('--disable-background-networking')
chrome_options.add_argument('--disable-sync')
chrome_options.add_argument('--disable-default-apps')
chrome_options.add_argument('--incognito')
driver = webdriver.Chrome(options=chrome_options)

# clear cookies before starting
driver.delete_all_cookies()

# directory path to place the generated HAR files 
HAR_DIRECTORY = '/Users/adrianrivera/Desktop/EEC 173A (ECS 152)/Project 2/HAR_Files/'

driver.set_page_load_timeout(120)

# read the csv file
with open("top-1m.csv", newline="") as file:
    sites_from_csv = list(csv.reader(file, delimiter=","))

# variables to track crawling process
current_site_index = 0
sites_succesfully_visted = 0
sites_unseccesfully_visited = 0

while sites_succesfully_visted < 1000:
    try:
        # do crawling
        site_name = sites_from_csv[current_site_index][1]
        proxy.new_har(site_name, options={'captureHeaders': True, 'captureCookies': True})

        # attempt to visit the site
        driver.get("http://" + site_name)

        # write har file
        with open(f"{HAR_DIRECTORY}{current_site_index + 1}_{site_name}.har", "w") as f:
            f.write(json.dumps(proxy.har))

        sites_succesfully_visted += 1  
        print(f'Visited: {site_name}')

    except TimeoutException:
        print(f'Timeout for site {sites_from_csv[current_site_index][1]}')
        sites_unseccesfully_visited += 1 

    except Exception as error_loading:
        print(f'Error visiting {sites_from_csv[current_site_index][1]}: {error_loading}')
        sites_unseccesfully_visited += 1  

    current_site_index += 1

# stop server and exit
server.stop()
driver.quit()

# summary of crawling results
print(f'{sites_succesfully_visted} sites visited successfully and {sites_unseccesfully_visited} sites unfortunately failed.')
