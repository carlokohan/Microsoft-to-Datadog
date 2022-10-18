"""
    Configuration environments for Azure Logs Integration

    Created by Jose Carlo Husmillo on 11/26/21

    *This assumes that environment variables for Datadog api are declared before running*
"""
import requests
import datetime
import sys
import json
import logging
import time


#datadog
import os
from dateutil.parser import parse as dateutil_parser
from datadog_api_client.v2 import ApiClient, ApiException, Configuration
from datadog_api_client.v2.api import logs_api
from datadog_api_client.v2.models import *
# See configuration.py for a list of all supported configuration parameters.
configuration = Configuration()

login_url = 'https://login.microsoftonline.com/'
resource = 'https://graph.microsoft.com'

logger = logging.getLogger("azure-auditLogs")
logger.setLevel(logging.DEBUG)
filehdr = logging.FileHandler('handler-logs.txt')
filehdr.setLevel(logging.INFO)
print(logger.addHandler(filehdr))
logger.info("Initialized logger.")

def send_logs(client_id, client_secret, tenant_domain, environment):
    # Get an OAuth access token
    bodyvals = {'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials',
                'resource': resource}
    ddsource_val = "Azure_B2C_" + environment
    ddtags_val = "env:" + environment + ",version:1.0"
    hostname_val = "Azure_B2C_" + environment
    service_val ="B2C_" + environment
    
    request_url = login_url + tenant_domain + '/oauth2/token'
    token_response = requests.post(request_url, data=bodyvals)
    
    access_token = token_response.json().get('access_token')
    token_type = token_response.json().get('token_type')
    
    if access_token is None or token_type is None:
        logger.info("ERROR: Couldn't get access token")
    
    # Use the access token to make the API request
    yesterday = datetime.date.strftime(datetime.date.today() - datetime.timedelta(days=1), '%Y-%m-%d')
    today = datetime.date.strftime(datetime.date.today(), '%Y-%m-%d')
    
    last_hour = datetime.datetime.now() - datetime.timedelta(hours = 1)
    time_now = datetime.datetime.now()
    
    final_token = token_type + ' ' + access_token
    header_params = {'Authorization': final_token}
    #past day:
    #request_string = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?&$filter=activityDateTime ge ' + yesterday + ' and activityDateTime le ' + today
    #past 1 hour:
    request_string = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?&$filter=activityDateTime ge ' + last_hour.strftime('%Y-%m-%dT%H:%M:%SZ') + ' and activityDateTime le ' + time_now.strftime('%Y-%m-%dT%H:%M:%SZ')
    #make date as specific to yesterday only so no double entries
    response = requests.get(request_string, headers = header_params)
    
    if response.status_code is 200:
        data = json.loads(response.content)
        logs = data['value']
        
        # Enter a context with an instance of the API client
        with ApiClient(configuration) as api_client:
            # Create an instance of the API class
            api_instance = logs_api.LogsApi(api_client)
            
            for log_entry in logs:
                log_entry["targetResources"].append({"initiatedBy": log_entry["initiatedBy"]})
                log_entry["targetResources"].append({"activityDateTime": log_entry["activityDateTime"]})
                log_entry["targetResources"].append({"activityDisplayName": log_entry["activityDisplayName"]})
                log_entry["targetResources"].append({"correlationId": log_entry["correlationId"]})
                log_entry["targetResources"].append({"resultReason": log_entry["resultReason"]})
                log_entry["targetResources"].append({"result": log_entry["result"]})
                log_entry["targetResources"] = str(log_entry["targetResources"])
    
                body = HTTPLog([
                    HTTPLogItem(
                        ddsource=ddsource_val,
                        ddtags=ddtags_val,
                        hostname=hostname_val,
                        message=json.dumps(log_entry),
                        service=service_val,
                    ),
                ])  # HTTPLog | Log to send (JSON format).
                content_encoding = ContentEncoding("gzip")  # ContentEncoding | HTTP header used to compress the media-type. (optional)
                ddtags = "env:development,user:datadog"  # str | Log tags can be passed as query parameters with `text/plain` content type. (optional)
            
                try:
                    # Send logs
                    api_response = api_instance.submit_log(body, content_encoding=content_encoding, ddtags=ddtags)
                    logger.info(str(api_response) + " Success sending logs")
                except ApiException as e:
                    logger.info("Exception when calling LogsApi->submit_log: %s\n" % e)
    else:
        logger.info('Error on Microsoft API')
        logger.info(response.content)


#azure
if __name__ == "__main__":
    while True:
        logger.info("Starting Azure log forwarder")
        try:
            logger.info("Starting SSO dev environment")
            client_id = 'xxx' #from Azure, after registering app
            client_secret = 'xxx'
            tenant_domain = 'xxx'
            environment = 'dev'
            
            send_logs(client_id, client_secret, tenant_domain, environment)
            
            """
            logger.info("Starting SSO stg environment")
            client_id = 'xxx' #from Azure, after registering app
            client_secret = 'xxx'
            tenant_domain = 'xxx'
            environment = 'stg'
            
            send_logs(client_id, client_secret, tenant_domain, environment)
            
            logger.info("Starting SSO prod environment")
            client_id = 'xxx' #from Azure, after registering app
            client_secret = 'xxx'
            tenant_domain = 'xxx'
            environment = 'prd'
            
            send_logs(client_id, client_secret, tenant_domain, environment)
            
            
            logger.info("Starting Azure AD of employees environment")
            client_id = 'xxx' #from Azure, after registering app, Application (client) id
            client_secret = 'xxx'
            tenant_domain = 'xxx'
            environment = 'swp'
            
            send_logs(client_id, client_secret, tenant_domain, environment)
            """
            
            logger.info("Sleeping for 1 hour")
            time.sleep(3600)
        except Exception as e:
            logger.info("Error occured.")
            
        logger.info("Done 1 attempt")
