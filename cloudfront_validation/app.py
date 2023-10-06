import json
import hmac
import hashlib
import base64
from urllib.parse import parse_qs


def generate_hash(secret, message):
    hash_obj = hmac.new(secret.encode('utf-8'),
                        message.encode('utf-8'), hashlib.sha256)
    calculated_hash = base64.b64encode(hash_obj.digest()).decode()
    return calculated_hash


def multiply_non_zero_numbers(sequence):
    array = list(sequence)

    result = 1

    for element in array:
        number = int(element)

        if number != 0:
            result *= number

    return result


def generate_dynamic_secret_key(ip, agent, session_id):
    raw_ip = ip.replace(".", "")
    ip_product = multiply_non_zero_numbers(raw_ip)

    dynamic_secret_key = str(
        ip_product) + agent.replace(" ", "") + session_id.replace(" ", "")

    return dynamic_secret_key


def validate_token(token, ip, agent, session_id):
    dynamic_secret_key = generate_dynamic_secret_key(ip, agent, session_id)
    calculated_hash = generate_hash(dynamic_secret_key, ip)

    if calculated_hash == token:
        return True
    else:
        return False


def lambda_handler(event, context):

    request = event['Records'][0]['cf']['request']
    headers = request['headers']
    params = parse_qs(request["querystring"])
    jsessionid = params.get('JSESSIONID', None)

    if headers.get('authorization') is None or headers.get('user-agent') is None:
        return {
            'status': '400',
            'statusDescription': 'Bad Request',
            'body': 'Missing Required Headers'
        }

    if jsessionid is None:
        return {
            'status': '400',
            'statusDescription': 'Bad Request',
            'body': 'Missing Required Parameters'
        }

    bearer_token = headers.get('authorization')[0]['value'].split(' ')[1]
    client_ip = request['clientIp']
    user_agent = headers.get('user-agent')[0]['value']

    if not validate_token(bearer_token, client_ip, user_agent, jsessionid[0]):
        return {
            'status': '403',
            'statusDescription': 'Forbidden',
            'body': 'Invalid Token'
        }

    return request
