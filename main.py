import logging
import argparse
from hashlib import md5
from os import getenv
from pathlib import Path
from time import localtime
from datetime import datetime, timedelta
import magic
from botocore.exceptions import ClientError
import boto3
from dotenv import load_dotenv

load_dotenv()


def init_client():
    try:
        client = boto3.client(
            "s3",
            aws_access_key_id=getenv("aws_access_key_id"),
            aws_secret_access_key=getenv("aws_secret_access_key"),
            aws_session_token=getenv("aws_session_token"),
            region_name=getenv("Region")
            #  config=botocore.client.Config(
            #      connect_timeout=conf.remote_cfg["remote_timeout"],
            #      read_timeout=conf.remote_cfg["remote_timeout"],
            #      region_name=conf.remote_cfg["aws_default_region"],
            #      retries={
            #          "max_attempts": conf.remote_cfg["remote_retries"]}
        )
        # check if credentials are correct
        client.list_buckets()
        return client
    except ClientError as e:
        logging.error(e)


parser = argparse.ArgumentParser(
    description="CLI program that helps with S3 buckets.",
    prog='main.py',
    epilog='DEMO APP - 2 FOR BTU_AWS'
)

parser.add_argument("-lb",
                    "--list_buckets",
                    help="List already created buckets.",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument("-cb",
                    "--create_bucket",
                    help="Flag to create bucket.",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument("-bn",
                    "--bucket_name",
                    type=str,
                    help="Pass bucket name.",
                    default=None)

parser.add_argument("-bc",
                    "--bucket_check",
                    help="Check if bucket already exists.",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="True")

parser.add_argument("-uf",
                    "--upload_file",
                    type=str,
                    help="Upload file",
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument("-fn",
                    "--file_name",
                    type=str,
                    help="Pass file name.",
                    default=None)

parser.add_argument("-ver",
                    "--versioning",
                    type=str,
                    help="list bucket object",
                    nargs="?",
                    default=None)

parser.add_argument("-l_o_v",
                    "--list_object_versions",
                    help="list versions",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

parser.add_argument("-d_v",
                    "--delete_version",
                    help="delete version",
                    choices=["False", "True"],
                    type=str,
                    nargs="?",
                    const="True",
                    default="False")

def list_buckets(aws_s3_client):
    buckets = aws_s3_client.list_buckets()
    if buckets:
        for bucket in buckets['Buckets']:
            print(f'  {bucket["Name"]}')


def generate_file_name(file_extension) -> str:
    return f'up_{md5(str(localtime()).encode("utf-8")).hexdigest()}.{file_extension}'


def upload_local_file(aws_s3_client, bucket_name, filename, keep_file_name=False):
    mime_type = magic.Magic(mime=True)
    content_type = mime_type.from_file(filename)
    print(content_type)
    file_name = filename.split('/')[-1] \
        if keep_file_name \
        else generate_file_name(filename.split('/')[-1])
    print(file_name)

def versioning(aws_s3_client, bucket_name, status : bool):
    versioning_status = "Enabled" if status else "Suspended"
    aws_s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={
            "Status": versioning_status
        }
    )

def list_object_versions(aws_s3_client, bucket_name, file_name):
    versions = aws_s3_client.list_object_versions(
        Bucket=bucket_name,
        Prefix=file_name
    )

    for version in versions['Versions']:
        version_id = version['VersionId']
        file_key = version['Key'],
        is_latest = version['IsLatest']
        modified_at = version['LastModified']

        # response = aws_s3_client.get_object(
        #     Bucket=bucket_name,
        #     Key=file_key[0],
        #     VersionId=version_id,
        # )
        # data = response['Body'].read()

        print(version_id, file_key, is_latest, modified_at)

def delete_version(aws_s3_client, bucket_name):
    vers = aws_s3_client.list_object_versions(Bucket=bucket_name)['Versions']

    for i in vers:
        now = datetime.datetime.now()
        modified_at = i['LastModified']
        is_latest = i['IsLatest']
        m = now - modified_at

        if m > timedelta(days=180):
            aws_s3_client.delete_version(Bucket=bucket_name, Key=i['Key'], VersionId=i['VersionId'])


s3_client = init_client()
args = parser.parse_args()

if args.bucket_name:

    if args.list_buckets == "True":
        list_buckets(s3_client)

    if args.file_name and args.upload_file == "True":
        upload_local_file(s3_client, args.bucket_name, args.file_name, args.keep_file_name)

    if args.versioning == "True":
        versioning(s3_client,args.bucket_name, True)

    if args.list_object_versions == "True":
        list_object_versions(s3_client,args.bucket_name,args.file_name)

    if args.delete_version() == "True":
        delete_version(s3_client,args.bucket_name)
