# Introduction 
Node module to provide Azure shared key authorization strings for using storage REST API.

# Getting Started
Call the constructor with the storage account name and the shared key that will be used to sign requests to the REST API.
Call `getAuthHeaderValue` with the http request options and the `Authorization` header value will be returned. 
```javascript
const azureStorageSign = require("azureStorageSign");

let myAzureStorageSign = new azureStorageSign("account name", "Shared key");

let httpOtpions = {
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

httpOptions.headers.Authorization = myAzureStorageSign(httpOtions);
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
