import boto3
import time
import os
import json
from collections import defaultdict
from botocore.exceptions import NoCredentialsError, ClientError
from tqdm import tqdm

# Load AWS credentials from configuration file
def load_aws_credentials(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

CONFIG_FILE = 'data/aws_config.json'
DOWNLOAD_DIR = '/tmp/os_tests/os_tests/s3_bucket_virtqe-logs'
POLL_INTERVAL = 60 * 60 * 24  
EXCLUDED_PREFIX = 'rhengs/'  

aws_config = load_aws_credentials(CONFIG_FILE)

s3 = boto3.client(
    's3',
    aws_access_key_id=aws_config['aws_access_key_id'],
    aws_secret_access_key=aws_config['aws_secret_access_key'],
    region_name=aws_config['region_name']
)

# Function to list all objects in the S3 bucket, excluding the specified folder
def list_s3_objects(bucket):
    objects = []
    continuation_token = None
    try:
        while True:
            kwargs = {'Bucket': bucket}
            if continuation_token:
                kwargs['ContinuationToken'] = continuation_token

            response = s3.list_objects_v2(**kwargs)

            if 'Contents' in response:
                objects.extend(response['Contents'])

            if response.get('IsTruncated'):  # More objects exist, retrieve the next batch
                continuation_token = response.get('NextContinuationToken')
            else:
                break

        # Exclude objects that start with the specified prefix (rhengs/ and its subdirectories)
        return [item['Key'] for item in objects if not item['Key'].startswith(EXCLUDED_PREFIX)]
    except ClientError as e:
        print(f"Error fetching objects from S3: {e}")
        return []

# Function to list first-level folders in the S3 bucket, excluding specified folder
def list_first_level_folders(bucket):
    objects = list_s3_objects(bucket)
    first_level_folders = set()

    for obj in objects:
        first_level_folder = obj.split('/')[0] + '/'
        if first_level_folder != EXCLUDED_PREFIX and first_level_folder not in first_level_folders:
            first_level_folders.add(first_level_folder)
    
    return list(first_level_folders)

# Function to download an S3 object, maintaining folder structure
def download_s3_object(bucket, object_key, download_dir):
    local_file_path = os.path.join(download_dir, object_key)

    if not os.path.exists(os.path.dirname(local_file_path)):
        os.makedirs(os.path.dirname(local_file_path))

    if object_key.endswith('/'):
        return False  
    if os.path.exists(local_file_path):
        print(f"File {local_file_path} already exists. Skipping...")
        return False  

    try:
        s3.download_file(bucket, object_key, local_file_path)
        object_metadata = s3.head_object(Bucket=bucket, Key=object_key)
        return object_metadata['ContentLength']  
    except NoCredentialsError:
        print("Credentials not available")
    except ClientError as e:
        print(f"Error downloading {object_key}: {e}")
    
    return False  

# Function to calculate current download speed and estimate remaining time
def calculate_download_speed(total_downloaded_bytes, elapsed_time):
    if elapsed_time > 0:
        download_speed = total_downloaded_bytes / elapsed_time  
        return download_speed  
    return 0

# Group files by folder for summary info
def group_files_by_folder(file_keys):
    folder_summary = defaultdict(list)
    for file_key in file_keys:
        folder_name = file_key.split('/')[0]  
        folder_summary[folder_name].append(file_key)
    return folder_summary

# Monitor and download all files and folders, excluding the specified folder
def monitor_and_download(bucket, download_dir, interval):
    downloaded_objects = set()
    total_files = 0
    total_folders = 0
    downloaded_files = 0
    downloaded_folders = 0
    total_downloaded_bytes = 0
    start_time = time.time()

    while True:
        current_objects = set(list_s3_objects(bucket))

        unique_folders = set()

        # Count total files and folders (before skipping existing files)
        for object_key in current_objects:
            if object_key.endswith('/'):
                unique_folders.add(object_key)
            else:
                total_files += 1

        total_folders = len(unique_folders)

        # Filter out already downloaded (or existing) objects before counting new objects
        new_objects = set()
        for object_key in current_objects - downloaded_objects:
            local_file_path = os.path.join(download_dir, object_key)
            if not os.path.exists(local_file_path) and not object_key.endswith('/'):
                new_objects.add(object_key)

        remaining_files = len(new_objects)

        if new_objects:
            # Group new files by folder
            folder_summary = group_files_by_folder(new_objects)
            print("\nSummary of new files to download by folder:")
            for folder, files in folder_summary.items():
                print(f"- {folder}: {len(files)} files")

            # Start downloading new files
            with tqdm(total=remaining_files, desc="Downloading objects", unit="file") as pbar:
                for object_key in new_objects:
                    downloaded_size = download_s3_object(bucket, object_key, download_dir)
                    downloaded_objects.add(object_key)

                    if downloaded_size:
                        downloaded_files += 1
                        total_downloaded_bytes += downloaded_size
                        pbar.update(1)

                    # Update download speed in MB/s
                    elapsed_time = time.time() - start_time
                    current_speed = calculate_download_speed(total_downloaded_bytes, elapsed_time)
                    if current_speed > 0:
                        pbar.set_postfix_str(f"Speed: {current_speed / (1024 * 1024):.2f} MB/s")

            # Print the status after each batch of downloads
            elapsed_time = time.time() - start_time
            current_speed = calculate_download_speed(total_downloaded_bytes, elapsed_time)

            print(f"\nTotal files: {total_files}, Total folders: {total_folders}")
            print(f"Downloaded files: {downloaded_files}, Downloaded folders: {downloaded_folders}")
            print(f"Remaining files: {remaining_files}")
            print(f"Current overall download speed: {current_speed / (1024 * 1024):.2f} MB/s")
        else:
            print("No new objects found.")

        # Calculate the overall download speed
        elapsed_time = time.time() - start_time
        current_speed = calculate_download_speed(total_downloaded_bytes, elapsed_time)
        print(f"Current overall download speed: {current_speed / (1024 * 1024):.2f} MB/s")

        print(f"Waiting for {interval} seconds before the next check...\n")
        time.sleep(interval)

if __name__ == "__main__":
    BUCKET_NAME = "virtqe-logs"

    print("Checking new instance test logs to download:")
    folders = list_first_level_folders(BUCKET_NAME)
    for folder in folders:
        print(f"- {folder}")

    monitor_and_download(BUCKET_NAME, DOWNLOAD_DIR, POLL_INTERVAL)
