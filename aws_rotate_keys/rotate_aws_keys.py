from base64 import b64encode
from nacl import encoding, public
import requests
import os
import boto3
from botocore.exceptions import ClientError, ParamValidationError

iam = boto3.client('iam')
aws_user = os.environ['AWS_TERRA_USER']
access_token = os.environ['GITHUB_ACCESS_TOKEN']
github_repository = os.environ['GITHUB_REPO']
github_access_key_id_secret_name = os.environ['GITHUB_SECRET_ACCESS_KEY_ID']
github_secret_access_key_secret_name = os.environ['GITHUB_SECRET_SECRET_ACCESS_KEY']


def encrypt_secret_before_update(public_key, secret_value):
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def update_secret_in_github(public_key_id, secret_name, secret_value):
    data = {"encrypted_value": secret_value, "key_id": public_key_id}
    response = requests.put("https://api.github.com/repos/{}/actions/secrets/{}".format(github_repository, secret_name),
                            json=data,
                            headers={'Content-Type': 'application/json',
                                     'Authorization': 'token {}'.format(access_token),
                                     'Cache-Control': 'no-cache',
                                     'Pragma': 'no-cache'})
    return response.status_code


def get_github_public_key():
    """return the github api public key"""
    response = requests.get("https://api.github.com/repos/{}/actions/secrets/public-key".format(github_repository),
                            headers={'Content-Type': 'application/json',
                                     'Authorization': 'token {}'.format(access_token)})
    data = response.json()
    return {'public_key_id': data['key_id'], 'public_key': data['key']}


# Create an access key
def create_access_key():
    try:
        response = iam.create_access_key(
            UserName=aws_user
        )
        access_key = response['AccessKey']['AccessKeyId']
        secret_access_key = response['AccessKey']['SecretAccessKey']
        return access_key, secret_access_key
    except ClientError as e:
        if e.response['Error']['Code'] == 'LimitExceededException':
            print("User already has two keys, cannot add more")
            raise


def number_of_keys_for_an_user():
    # See if IAM user already has more than one key
    paginator = iam.get_paginator('list_access_keys')
    try:
        for response in paginator.paginate(UserName=aws_user):
            return len(response['AccessKeyMetadata'])
    except ParamValidationError as e:
        raise


def delete_inactive_access_key():
    try:
        for access_key in iam.list_access_keys(UserName=aws_user)['AccessKeyMetadata']:
            if access_key['Status'] == 'Inactive':
                # Delete the access key.
                print('Deleting inactive access key {0}.'.format(access_key['AccessKeyId']))
                response = iam.delete_access_key(
                    UserName=aws_user,
                    AccessKeyId=access_key['AccessKeyId']
                )
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            print("Not authorized to perform iam upgrade")
            raise


def delete_currently_not_used_access_key():
    response = iam.list_access_keys(UserName=aws_user)
    access_key_0 = response['AccessKeyMetadata'][0]['AccessKeyId']
    access_key_1 = response['AccessKeyMetadata'][1]['AccessKeyId']
    last_used_date_key_0 = iam.get_access_key_last_used(AccessKeyId=access_key_0)['AccessKeyLastUsed']['LastUsedDate']
    last_used_date_key_1 = iam.get_access_key_last_used(AccessKeyId=access_key_1)['AccessKeyLastUsed']['LastUsedDate']
    delete_access_key(access_key_0) if last_used_date_key_0 < last_used_date_key_1 else delete_access_key(access_key_1)
    print("Deleted the key which is currently not used.")


def delete_older_access_key():
    if number_of_keys_for_an_user() == 2:
        response = iam.list_access_keys(UserName=aws_user)
        create_date_access_key_0 = response['AccessKeyMetadata'][0]["CreateDate"]
        create_date_access_key_1 = response['AccessKeyMetadata'][1]["CreateDate"]
        if create_date_access_key_0 < create_date_access_key_1:
            delete_access_key(response['AccessKeyMetadata'][0]["AccessKeyId"])
        else:
            delete_access_key(response['AccessKeyMetadata'][1]["AccessKeyId"])
        print("Deleted the old key.")


def delete_access_key(access_key):
    response = iam.delete_access_key(
        AccessKeyId=access_key,
        UserName=aws_user,
    )


def update_github_secret(secret_name, secret_value):
    public_key_data = get_github_public_key()
    encrypted_secret_value = encrypt_secret_before_update(public_key_data['public_key'], secret_value)
    update_secret_in_github(public_key_data['public_key_id'], secret_name, encrypted_secret_value)


def delete_keys_with_no_last_active_date():
    response = iam.list_access_keys(UserName=aws_user)
    for access_key_metadata in response['AccessKeyMetadata']:
        access_key = access_key_metadata['AccessKeyId']
        if 'LastUsedDate' not in iam.get_access_key_last_used(AccessKeyId=access_key)['AccessKeyLastUsed']:
            delete_access_key(access_key)
            print("Deleted never used access key - " + access_key)


if __name__ == '__main__':
    delete_inactive_access_key()
    delete_keys_with_no_last_active_date()
    if number_of_keys_for_an_user() == 2:
        print("Two keys detected. The key with lesser last accessed date will be deleted.")
        delete_currently_not_used_access_key()
    new_key = create_access_key()
    print(update_github_secret(github_access_key_id_secret_name, new_key[0]))
    print(update_github_secret(github_secret_access_key_secret_name, new_key[1]))
    delete_older_access_key()
