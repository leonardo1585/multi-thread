import functools
import time
import requests
import threading
import pandas as pd
import re
from collections import defaultdict
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv


request_count = 0
line_count = 0
start_time = datetime.now()

class RateLimiter:
    def __init__(self, key_prefix, calls, period):
        self.key_prefix = key_prefix
        self.calls = calls
        self.period = timedelta(seconds=period)
        self.store = defaultdict(int)
        self.timestamps = defaultdict(list)
        self.lock = threading.Lock()

    def _get_key(self, identifier):
        return f"{self.key_prefix}:{identifier}"

    def check(self, identifier):
        key = self._get_key(identifier)
        now = datetime.now()

        with self.lock:
            self.timestamps[key] = [timestamp for timestamp in self.timestamps[key] if timestamp > now - self.period]
            self.timestamps[key].append(now)
            self.store[key] = len(self.timestamps[key])

            current_count = self.store[key]

            if current_count > self.calls:
                print(
                    f"Rate limit [{current_count}/{self.calls}] was reached, in {self.period.total_seconds()} seconds, "
                    f"for key {key}. Waiting for 20 seconds."
                )
                time.sleep(20)


def rate_limit_and_retry_on_exception(domain_key_func, calls_per_period, period):
    def decorator(func):
        rate_limiter = RateLimiter("rate_limit", calls_per_period, period)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            global request_count
            domain = domain_key_func(*args, **kwargs)
            max_attempts = 8
            sleep_time = 1
            attempts = 0
            last_exception = ""

            while attempts < max_attempts:
                try:
                    rate_limiter.check(domain)
                    request_count += 1
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    status_code = e.status_code if hasattr(e, "status_code") else None
                    if not status_code:
                        raise

                    if status_code == 404:
                        print(f"Not Found: {str(e)}. Not retrying this.")
                        break
                    elif status_code == 500:
                        print(f"A 500 error occurred: {str(e)}. Retrying...")
                        raise

                    if attempts >= 2:
                        if status_code == 429:
                            print(f"Too many requests: {str(e)}. Retrying...")
                        elif status_code == 408:
                            print(f"Timeout error: {str(e)}. Retrying...")
                        else:
                            raise

                print(
                    f"Retrying... Attempt {attempts + 1} after {sleep_time} seconds, in {func.__name__}:"
                )
                time.sleep(sleep_time)
                attempts += 1
                sleep_time *= 2

            message = (
                f"Rate limit exceeded, max retry attempts reached. Last error in {func.__name__}:"
                f"Last error:{last_exception}, after {attempts} attempts."
            )

            print(message)
            raise Exception(message)

        return wrapper

    return decorator


class RequestClient:
    def make_request(
            self,
            url: str,
            method: str,
            headers=None,
            data=None,
            params=None,
            files=None,
            json=None,
    ):
        global request_count
        request_count += 1

        if data and json:
            raise ValueError("Cannot use both 'data' and 'json' arguments simultaneously.")

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json,
                data=data,
                timeout=60,
                params=params,
                files=files,
            )

            response.raise_for_status()

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err} - {response.content}")
            raise
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            raise
        else:
            return response


class VtexAuthorization(RequestClient):
    def __init__(self, app_key, app_token):
        self.app_key = app_key
        self.app_token = app_token

    def _get_headers(self):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-VTEX-API-AppKey": self.app_key,
            "X-VTEX-API-AppToken": self.app_token,
        }
        return headers


class VtexPrivateClient(VtexAuthorization):
    VTEX_CALLS_PER_PERIOD = 1500
    VTEX_PERIOD = 60

    @rate_limit_and_retry_on_exception(
        lambda self, sku_id, domain: domain, calls_per_period=VTEX_CALLS_PER_PERIOD, period=VTEX_PERIOD
    )
    def get_product_details(self, sku_id, domain):
        url = (
            f"https://{domain}/api/catalog_system/pvt/sku/stockkeepingunitbyid/{sku_id}"
        )
        headers = self._get_headers()
        max_attempts = 10
        attempts = 0
        sleep_time = 5

        while attempts < max_attempts:
            try:
                response = self.make_request(url, method="GET", headers=headers)
                return response.json()
            except requests.exceptions.HTTPError as http_err:
                if http_err.response.status_code == 404:
                    print(f"SKU not found: {sku_id}")
                    return None
                elif http_err.response.status_code == 429:
                    attempts += 1
                    print(f"Too many requests: {str(http_err)}. Attempt {attempts}/{max_attempts}. Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                    sleep_time *= 2
                else:
                    raise
            except requests.exceptions.RequestException as req_err:
                attempts += 1
                print(f"Request error occurred for SKU {sku_id}: {str(req_err)}. Attempt {attempts}/{max_attempts}. Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
                sleep_time *= 2

        print(f"Failed to fetch SKU {sku_id} after {max_attempts} attempts")
        return None

def write_to_csv(file_path, data):
    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(data)


def calculate_average_requests_per_minute(start_time, request_count):
    elapsed_time = datetime.now() - start_time
    elapsed_minutes = elapsed_time.total_seconds() / 60
    if elapsed_minutes > 0:
        return request_count / elapsed_minutes
    return 0


def print_average_requests_periodically():
    while True:
        time.sleep(60)
        average_requests_per_minute = calculate_average_requests_per_minute(start_time, request_count)
        print(f"Média de requisições por minuto: {average_requests_per_minute:.2f}")

def process_sku(row, client, domain, file_path):
    global line_count
    line_count += 1
    query_string = row["rclastcart"]

    query_string = str(query_string)

    skus = re.findall(r'sku=(\d+)', query_string)

    sku_results = []

    print(f"Quantidade de linhas percorridas - {line_count}")

    for sku_id in skus:
        product_details = client.get_product_details(sku_id, domain)
        print(f"Quantidade de requests feitas - {request_count}")

        if product_details and "ProductCategories" in product_details:
            categories = product_details["ProductCategories"].values()
            sku_results.extend(categories)
        else:
            sku_results.append("Failed to fetch details")

        data = [query_string, sku_id, ', '.join(sku_results)]
        write_to_csv(file_path, data)

def find_missing_data(df1, df2, key_column):
    df1_set = set(df1[key_column].dropna())
    df2_set = set(df2[key_column].dropna())
    missing_data = df1_set - df2_set
    return pd.DataFrame(list(missing_data), columns=[key_column])


if __name__ == "__main__":
    app_key = "APP_KEY"
    app_token = "APP_TOKEN"
    domain = "dominio"

    request_count = 0
    line_count = 0
    start_time = datetime.now()

    client = VtexPrivateClient(app_key, app_token)

    threading.Thread(target=print_average_requests_periodically, daemon=True).start()

    csv_file_path = 'output.csv'


    if not pd.io.common.file_exists(csv_file_path):
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Colunas que serão criadas no novo CSV
            writer.writerow(["query_string", "sku_id", "categories"])
    # Arquivo a ser lido
    df = pd.read_excel("lastcart - C&V.xlsx")

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(process_sku, row, client, domain, csv_file_path) for index, row in df.iterrows()]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"An error occurred: {str(e)}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        print("Saving the results accumulated so far to CSV.")
        print(f"Total requests feitas: {request_count}")
        print(f"Total linhas percorridas: {line_count}")
        raise

    print(f"Finished processing SKUs. Results saved to CSV.")
    print(f"Total requests feitas: {request_count}")
    print(f"Total linhas percorridas: {line_count}")

    average_requests_per_minute = calculate_average_requests_per_minute(start_time, request_count)
    print(f"Média de requisições por minuto: {average_requests_per_minute:.2f}")