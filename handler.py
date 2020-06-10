#import subprocess
import boto3
import base64
import os

def hello(event, context):
    client = boto3.client('kms')

    public_key_result = client.get_public_key(KeyId=os.environ['key_arn'], GrantTokens=[])

    sign_response = client.sign(
        KeyId=os.environ['key_arn'],
        Message=b'hello world', #Messages can be 0-4096 bytes. To sign a larger message, provide the message digest
        MessageType='RAW', # or 'DIGEST'
        GrantTokens=[],
        SigningAlgorithm='ECDSA_SHA_256'
    )

    return {
        "publickey": base64.b64encode(public_key_result['PublicKey']), #DER-encoded X.509 public key, also known as SubjectPublicKeyInfo (SPKI)
        "signature": base64.b64encode(sign_response['Signature']) #DER encoded ANS X9.62-2005
    }

    #return {
    #    "publickey": subprocess.check_output("aws kms get-public-key --key-id arn:aws:kms:eu-central-1:129012979237:key/e19d3f84-24d2-40bf-b8e8-d03e07ae2de0",shell=True) #aws cli not installed :-(
    #}
