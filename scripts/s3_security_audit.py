import sys
import boto3
import json
from botocore.exceptions import ClientError

def print_warning(message):
    # ANSI escape code for red text
    print(f"\033[91m{message}\033[0m")  # Red text

def print_category(message):
    # ANSI escape code for cyan text
    print(f"\033[96m{message}\033[0m")  # Cyan text

def print_json(message):
    # ANSI escape code for yellow text
    print(f"\033[93m{message}\033[0m")  # Yellow text

def get_bucket_ownership_controls(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
        print_json(json.dumps(response, indent=4))
    except ClientError as e:
        print_warning(f"Failed to retrieve Bucket Ownership Controls: {e}")

def get_bucket_lifecycle_policy(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        print_json(json.dumps(response, indent=4))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            print("No lifecycle configuration set for this bucket.")
        else:
            print_warning(f"Failed to retrieve lifecycle configuration: {e}")

def get_mfa_delete_settings(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        print_json(f"MFA Delete setting: {json.dumps(response.get('MFADelete', 'Disabled'), indent=4)}")
    except ClientError as e:
        print_warning(f"Failed to retrieve MFA Delete setting: {e}")

def check_external_sharing(s3_client, bucket_name):
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = json.loads(policy['Policy'])
        external_shared = False
        for statement in policy_document['Statement']:
            principal = statement.get('Principal')
            if isinstance(principal, dict) and 'AWS' in principal and principal['AWS'] != f"arn:aws:iam::{boto3.client('sts').get_caller_identity().get('Account')}:root":
                external_shared = True
                print_warning(f"Security Risk: Bucket {bucket_name} is shared with external AWS account via policy: {principal['AWS']}")
        if not external_shared:
            print("No external sharing detected in bucket policy.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            print("No bucket policy found for {bucket_name}.")
        else:
            print_warning("Error checking bucket policy for external sharing:", e)

    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        external_acl = False
        for grant in acl['Grants']:
            grantee = grant['Grantee']
            if grantee['Type'] == 'CanonicalUser' and grantee.get('ID') != s3_client.get_bucket_acl(Bucket=bucket_name)['Owner']['ID']:
                external_acl = True
                print_warning(f"Security Risk: Bucket {bucket_name} may be shared with external account via ACL.")
        if not external_acl:
            print("No external access detected in ACL.")
    except ClientError as e:
        print_warning("Error checking bucket ACL for external sharing:", e)

def get_s3_configurations(bucket_name):
    s3_client = boto3.client('s3')

    categories = {
        "Encryption Settings": ["get_bucket_encryption"],
        "Least Privilege Settings": ["get_bucket_acl", "get_bucket_policy"],
        "Exposure Settings": ["get_public_access_block"],
        "Data Management Settings": ["get_bucket_versioning", "get_bucket_logging"],
        "Cross-Origin Resource Sharing (CORS)": ["get_bucket_cors"],
        "Tagging and Metadata": ["get_bucket_tagging"],
        "Website Configuration": ["get_bucket_website"]
    }

    for category, methods in categories.items():
        print_category(f"\n{category}:")
        for method_name in methods:
            try:
                response = getattr(s3_client, method_name)(Bucket=bucket_name)
                if method_name == 'get_bucket_encryption':
                    if 'ServerSideEncryptionConfiguration' not in response:
                        print_warning("Security Risk: Encryption is not configured on this bucket.")
                    else:
                        print_json(json.dumps(response, indent=4))
                elif method_name == 'get_public_access_block':
                    if 'PublicAccessBlockConfiguration' not in response:
                        print_warning("Security Risk: Public access block is not configured on this bucket.")
                    else:
                        print_json(json.dumps(response, indent=4))
                else:
                    print_json(json.dumps(response, indent=4))
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucket':
                    print_warning(f"Bucket '{bucket_name}' does not exist.")
                    break
                elif e.response['Error']['Code'] == 'AccessDenied':
                    print_warning(f"Access denied to {method_name}.")
                else:
                    print_warning(f"Error fetching {method_name}: {e}")

    # Additional security configurations
    get_mfa_delete_settings(s3_client, bucket_name)
    get_bucket_ownership_controls(s3_client, bucket_name)
    get_bucket_lifecycle_policy(s3_client, bucket_name)
    check_external_sharing(s3_client, bucket_name)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <bucket_name>")
        sys.exit(1)

    bucket_name = sys.argv[1]
    get_s3_configurations(bucket_name)
