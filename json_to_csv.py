""" 
This code is only an example, it is not intended to be used in production
virtual environments like venv or poetry are best practice to install packages
other packages that may be useful to manipulate data are toolz or panda
This code is only an example, it is not intended to be used in production
"""
import json
import csv
import datetime
import sys
from cpapi import APIClient, APIClientArgs


def create_feed(feed_name: str) -> [dict]:
    """
       use management API to login, add threat feed, publish, and install-policy
       Args:
           string with feed name.
       Returns:

       """
    api_response = []

    client_args = APIClientArgs(server='172.16.1.1')
    # password = getpass.getpass("Enter password:")

    with APIClient(client_args) as client:
        try:
            # other password approaches include bcrypt encrypted file, and keychain package
            api_response = client.login('admin', 'vpn123')
            print({'request': 'login', 'status_code': api_response.status_code})
        except TypeError:
            print("Login error occurred")
            return None
        api_response = client.api_call('add-threat-ioc-feed', {'name': feed_name,
                                                               'feed-url': 'https://172.16.1.30:5000/output/' + feed_name + '.csv',
                                                               "enabled": True})
        print({'request': 'add-threat-ioc-feed', 'status_code': api_response.status_code})

        publish_resp = client.api_call('publish')
        print({'request': 'publish', 'status_code': api_response.status_code})

        # change the name of the policy package if not Standard
        #  change the name(s) of the targets
        # literally takes two minutes to return a response
        print("Installing policy, this takes a few minutes")
        api_response = client.api_call('install-policy',
                                       {'policy-package': "Standard", 'threat-prevention': True,
                                        'targets': 'grimes3200'})
        print({'request': 'install-policy', 'status_code': api_response.status_code})
        return None


# arrange a parsed list of dictionaries in Check Point format
def format_cp_order(record: [dict]) -> [dict]:
    """
       converts an integer to standard Check Point confidence string
       Args:

       Returns:

       """
    from datetime import datetime

    # from SK132193 #UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT
    # create list of dictionaries that represent the cp standard format
    uniq = [{'uniq-name': datetime.utcnow().strftime('%Y%m%d%H%M%S%f')} for value in range(len(record))]
    std_cp_record = uniq

    # stitch lists of dictionaries together
    # v3.9+ [u | v for u, v in zip(uniq, iocvalue)]
    # <v3.9 [{**u, **v} for u, v in zip(uniq, iocvalue)]
    value = [{'value': item['indicator']} for item in record]
    std_cp_record = [first | second for first, second in zip(std_cp_record, value)]

    type = [{'type': item['type']} for item in record]
    std_cp_record = [first | second for first, second in zip(std_cp_record, type)]

    confidence = [{'confidence': item['confidence']} for item in record]
    std_cp_record = [first | second for first, second in zip(std_cp_record, confidence)]

    severity = [{'severity': item['severity']} for item in record]
    std_cp_record = [first | second for first, second in zip(std_cp_record, severity)]

    # in SK132193 examples IP product is AB, hash is AV
    product = [{'product': 'AB'} for value in range(len(record))]
    std_cp_record = [first | second for first, second in zip(std_cp_record, product)]

    comment = [{'comment': 'this is a comment'} for value in range(len(record))]
    std_cp_record = [first | second for first, second in zip(std_cp_record, comment)]
    return std_cp_record


# provide an array of keys to keep and the list of dict's
def remove_list_keys(keystokeep, json_data):
    """
       converts an integer to standard Check Point confidence string
       Args:

       Returns:

       """
    return [dict((k, v.get(k, None)) for k in keystokeep) for v in json_data]


# convert numeric confidence into standard Check Point strings
def map_simple_confidence(record: dict[str, int]) -> dict[str, str]:
    """
    converts an integer to standard Check Point confidence string
    Args:

    Returns:

    """
    # accepted confidence levels are shown in SK116254 low, low-medium, medium, medium-high, high
    cpconfidence = {'low': list(range(0, 20)),
                    'low-medium': list(range(20, 40)),
                    'medium': list(range(40, 60)),
                    'medium-high': list(range(60, 80)),
                    'high': list(range(80, 101))
                    }

    score = record['confidence']
    confidence = next(name for name, value in cpconfidence.items() if score in value)
    return {'confidence': confidence}


def convert_confidence_to_string(json: list[dict]) -> list[dict]:
    cpconfidence: []

    cpconfidence = [map_simple_confidence(v) for v in json]
    json = [first | second for first, second in zip(json, cpconfidence)]

    return json


def create_csv_file(feed_name: str, std_cp_record: list[dict]):
    """
        creates csv file in the output directory below where this script is executed
        Args:
            feed_name string and list of dictionaries in CP standard format
        Returns:
           stdout if json file is not provided
        """
    # indicators must include indicator, confidence, severity, type at minimum
    # open a file for writing
    columns = ['uniq-name', 'value', 'type', 'confidence', 'severity', 'product', 'comment']
    try:
        with open("./output/" + feed_name + '.csv', 'w') as data_file:
            # create the csv writer object
            csv_writer = csv.DictWriter(data_file, fieldnames=columns)
            csv_writer.writeheader()
            ret = csv_writer.writerows(std_cp_record)
            # can also write row by row using
            # each[criteria]
            data_file.close()
    except IOError as e:
        return e


def main():
    """
    checks command line inputs, calls functions that arrange data, write csv file, and creates ioc feed
    Args:
        argc and argv python3 json_to_csv.py [name of json file]
    Returns:
       stdout if json file is not provided
    """
    # indicators from each feed must include indicator, confidence, severity, type at minimum
    keystokeep = {'exampledata': ['indicator', 'confidence', 'severity', 'type'],
                  'anotherFeed': ['indictor', 'type', 'confidence', 'severity', 'feed name', 'campaign']}

    # target input file assumed to have .json suffix in command line parameters
    try:
        json_file = ' '.join([str(arg) for arg in sys.argv if arg.endswith(".json")])
        if not json_file:
            raise ValueError('json file name not found in parameters')
    except ValueError as e:
        print(e)
        sys.exit()

    with open("{0}".format(json_file), 'r') as f:
        json_data = json.load(f)

    parsed_json_response = remove_list_keys(keystokeep['exampledata'], json_data)
    parsed_json_response = convert_confidence_to_string(parsed_json_response)
    std_cp_record = format_cp_order(parsed_json_response)

    feed_name = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    create_csv_file(feed_name, std_cp_record)
    create_feed(feed_name)


if __name__ == "__main__":
    main()
