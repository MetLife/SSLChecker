# SSLChecker

## Overview

SSLChecker is a serverless API written in Python and running on Azure Functions. The API is based on Alban Diquet's [SSLyze](https://github.com/nabla-c0d3/sslyze) library. SSLChecker is used to identify obsolete versions of SSL/TLS (e.g., SSL 3.0, and TLS 1.0) on an endpoint, or perform a full scan to identify all supported versions of SSL/TLS on an endpoint.

## Pre-requisites

Development - To set up a local development environment, follow the guidance from Microsoft [here](https://docs.microsoft.com/en-us/azure/azure-functions/functions-create-first-azure-function-azure-cli?pivots=programming-language-python&tabs=bash%2Cbrowser).

Deployment - As part of the above setup, you will be able to deploy to Azure using the azure-cli. Additionally, Azure DevOps or another CI/CD tool is capable of deploying to Azure.

## Usage

Invoke the function on the command line using curl:

``` curl https://<functionname>.azurewebsite.net/api/{scan:alpha}/{view:alpha}/{target}/{port}```

There are four parts to pass to the URI: scan, view, target, and port.

"scan" is the type of scan: policy or full. Currently, the default policy prohibits using SSL 2.0/3.0 and TLS 1.0/1.1, so the policy scan will identify which unsupported ciphers are in use, if any. A full scan will report back all supported ciphers. In a future release I will make this configurable.

Since corporations often use [split-view DNS](https://en.wikipedia.org/wiki/Split-horizon_DNS), "view" in this context is the network viewpoint you want to scan, either internal or external. This is accomplished by specifying a valid DNS server to use for name resolution. The default value for external will use OpenDNS (e.g. 208.67.222.222). The default for internal will be 0.0.0.0 and will result in an error if a scan is attempted and no internal DNS server is specified. Please modify the config.ini file to use an internal DNS server.

"target" should be the DNS domain name or IP that you would like to scan (i.e., github.com or 140.82.113.4).

"port" is optional and if omitted will default to TCP 443.

## A Note on Authentication

Microsoft has extensive documentation on how to secure an HTTP endpoint in Azure Functions [here](https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger?tabs=csharp#secure-an-http-endpoint-in-production). There are two main ways to secure a function: Turn on App Service Authentication/Authorization for the function app, or use Azure API Management (APIM) to authenticate requests. Additionally, Azure functions support API key authorization that you can supply either as a query string variable or in a HTTP header. Microsoft states that API key authorization is not intended as a way to secure an HTTP trigger in production

By default, I have set the authLevel in the function.json file to *anonymous*. Please note, when running functions locally, authorization is disabled regardless of the specified authorization level.

If you plan on running SSLChecker on the internet, please consider one of the above options for authentication.

## Feedback

Send me mail at joe@metlife.com