[![Build Status](https://travis-ci.com/warerebel/azurerestauth.svg?branch=master)](https://travis-ci.com/warerebel/azurerestauth)
[![Coverage Status](https://coveralls.io/repos/github/warerebel/azurerestauth/badge.svg?branch=master)](https://coveralls.io/github/warerebel/azurerestauth?branch=master)
<br />

# Introduction
Node module to generate Azure shared key authorization strings for using the REST API.

# Getting Started
Call the constructor with the storage account name and the shared key that will be used to sign requests to the REST API.
Call `getAuthHeaderValue` with the http request options and the `Authorization` header value will be returned.
## Javascript

```javascript
const azureRestAuth = require("@warerebel/azurerestauth");

let myAzureRestAuth = new azureRestAuth.AzureSign("account name", "Shared key");

let httpOptions = {
    method: "GET",
    protocol: "https:",
    host: "testsite.blob.core.windows.net",
    path: "/container01/tmp.txt",
    headers: {
                "x-ms-version": "2015-07-08",
                "x-ms-client-request-id": "9251fa41-0ca4-4558-84ac-44ab027b8f1e",
                "x-ms-date": "Tue, 05 Jul 2016 06:48:26 GMT"
            },
}

 let authString = myAzureRestAuth.getAuthHeaderValue(httpOptions);

 httpOptions.headers.Authorization = authString;
```

## Typescript
```typescript
import {AzureSign, HttpOptions} from "@warerebel/azurerestauth";

let myAzureRestAuth = new AzureSign("account name", "Shared key");

let httpOptions: HttpOptions = {
    method: "GET",
    protocol: "https:",
    host: "testsite.blob.core.windows.net",
    path: "/container01/tmp.txt",
    headers: {
                "x-ms-version": "2015-07-08",
                "x-ms-client-request-id": "9251fa41-0ca4-4558-84ac-44ab027b8f1e",
                "x-ms-date": "Tue, 05 Jul 2016 06:48:26 GMT"
            },
}

let authString = myAzureRestAuth.getAuthHeaderValue(httpOptions);

if(!httpOptions.headers)
  httpOptions.headers = {};
httpOptions.headers.Authorization = authString;  
```

# Build and Test
Install dependencies with:
`npm install`

Run tests with:
`npm test`

Generate coverage with:
`npm run coverage`

# Compatibility
Compatible with Azure REST API versions 2014-02-14 and later
