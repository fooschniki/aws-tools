#!/user/bin/env python3

"""
rotator_mfa.py

Rotate AWS credentials, when MFA and role-based (assume role) access are in use.

Python requirements:
- boto3
- mfaConfig populated with personal identifiers

Run:
python3 rotator_mfa.py
 - this will prompt for MFA token
set environmental variables by running:
. ~/.aws/aws_exports.sh

References:
https://docs.python.org/3/library/configparser.html
https://aws.amazon.com/premiumsupport/knowledge-center/authenticate-mfa-cli/
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html#STS.Client.get_session_token
"""

import configparser
import os.path
import sys

import boto3
import pprint
import mfaConfig as mfa_cfg

mfa_code = input("Enter your MFA token: ")
serial_number = mfa_cfg.serial_number
credentials_file = mfa_cfg.credentials_file
aws_exports = mfa_cfg.aws_exports

''' Allowed values between 900 - 43200 sec (12 hrs). '''
TOKEN_DURATION = 43200
REGION = 'eu-west-1'

def get_tokens(serial_number=None, mfa_code=None):
    """ Get new session tokens with AWS Security Token Service.
        The default profile is used to get new tokens.
    """
    session = boto3.Session(profile_name='default')
    client = session.client('sts')

    response = client.get_session_token(
        DurationSeconds=TOKEN_DURATION,
        SerialNumber=serial_number,
        TokenCode=mfa_code
    )

    tokens = {
        'output': 'json',
        'region': REGION,
        'aws_access_key_id': response['Credentials']['AccessKeyId'],
        'aws_secret_access_key': response['Credentials']['SecretAccessKey'],
        'aws_session_token': response['Credentials']['SessionToken']
    }

    print(f"Token expiration: {response['Credentials']['Expiration']}")
    pprint.pprint(tokens)
    with open(aws_exports, 'w') as exports_file:
        exports_file.write('export AWS_ACCESS_KEY_ID="{}"\n'.format(response['Credentials']['AccessKeyId']))
        exports_file.write('export AWS_SECRET_ACCESS_KEY="{}"\n'.format(response['Credentials']['SecretAccessKey']))
        exports_file.write('export AWS_SECURITY_TOKEN="{}"\n'.format(response['Credentials']['SessionToken']))
        exports_file.write('export AWS_SESSION_TOKEN="{}"\n'.format(response['Credentials']['SessionToken']))
    os.system('chmod +x {}'.format(aws_exports))
    return tokens

def rotate(credentials_file, serial_number, mfa_code):
    """ Rotate sessions tokens for AWS CLI. """

    ''' Check that the required parameters have values. '''
    if not os.path.isfile(credentials_file):
        print('Credentials file is missing!')
        sys.exit()
    if not serial_number.startswith('arn:aws:iam:'):
        print('MFA Device ARN should have a correct value.')
        sys.exit()
    if len(mfa_code) != 6:
        print('MFA Code should contain 6 characters.')
        sys.exit()

    ''' Get the new session tokens from AWS. '''
    tokens = get_tokens(serial_number, mfa_code)

    ''' Set the new tokens to credentials config file. '''
    config = configparser.ConfigParser()
    config.read(credentials_file)

    config['mfa'] = tokens

    with open(credentials_file, 'w') as configfile:
        config.write(configfile)

    print('New session tokens have been set successfully.')

    sys.exit()

if __name__ == '__main__':
    rotate(credentials_file, serial_number, mfa_code)
