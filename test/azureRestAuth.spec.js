/* eslint-disable no-undef */
const azureSign = require("../lib/azureRestAuth");
const assert = require("assert");

describe("It generates azure shared key authorizaton string", function(){
   
    before(function(){
        myAzureSign = new azureSign("tsmatsuzsttest0001", "93K17Co74T2lDHk2rA+wmb/avIAS6u6lPnZrk2hyT+9+aov82qNhrcXSNGZCzm9mjd4d75/oxxOr6r1JVpgTLA=="); 
    });
    
    it("Produces a canonacolised string from x-ms- header values", function(){
        let testObject = {
            "not-ms-header": "test data",
            "x-ms-version": "2014-02-14",
            "x-ms-date": "Sat, 21   Feb 2015 00:48:38 GMT"
        };
        let expectedString = "x-ms-date:Sat, 21 Feb 2015 00:48:38 GMT\nx-ms-version:2014-02-14\n";
        assert.deepEqual(myAzureSign.canonicalisedHeaders(testObject), expectedString);
    });
    
    it("builds a string from a header object", function(){
        let date = new Date();
        let testObject = {
            method: "GET",
            headers: {
                "Content-Encoding": "gzip",
                "Content-Language": "en",
                "Content-MD5": "MD5String",
                "Content-Type": "application/json",
                nonstandard: "test",
                Date: date,
                "If-Modified-Since": "Tue, 05 Jul 2016 06:48:26 GMT",
                "If-Match": "itemOne",
                "If-None-Match": "itemTwo",
                "If-Unmodified-Since": "Tue, 07 Jul 2016 06:48:26 GMT",
                "Range": "testRange"
            }
        };
        let expectedString = "GET\ngzip\nen\n\nMD5String\napplication/json\n" + date + "\nTue, 05 Jul 2016 06:48:26 GMT\nitemOne\nitemTwo\nTue, 07 Jul 2016 06:48:26 GMT\ntestRange\n";
        assert.deepEqual(myAzureSign.headerString(testObject), expectedString);
    });
    
    it("signs the string", function(){
        let testObject = {
            method: "GET",
            headers: {
                "x-ms-version": "2015-07-08",
                "x-ms-client-request-id": "9251fa41-0ca4-4558-84ac-44ab027b8f1e",
                "x-ms-date": "Tue, 05 Jul 2016 06:48:26 GMT"
            },
            host: "tsmatsuzsttest0001.blob.core.windows.net",
            protocol: "https:",
            path: "/container01/tmp.txt"
        };
        assert.deepEqual(myAzureSign.getAuthHeaderValue(testObject), "SharedKey tsmatsuzsttest0001:sGX7uEBy8i9ldZtx8nLDeD3vX3AI/LB/3msK0oL7oMI=");
    });
    
    it("Produces a canonicalised resource string for accessing the resource", function(){
        let url = {
            protocol: "https:",
            host: "myaccount.blob.core.windows.net",
            path: "/mycontainer?restype=container&comp=metadata"
        };
        let urlTwo = {
            protocol: "https:",
            host: "myaccount-secondary.blob.core.windows.net",
            path: "/mycontainer/myblob"
        };
        let urlThree = {
            protocol: "https:",
            host: "myaccount.blob.core.windows.net",
            path: "/container?restype=container&comp=list&include=snapshots&include=metadata&include=uncommittedblobs"
        };
        let expected = "/tsmatsuzsttest0001/mycontainer\ncomp:metadata\nrestype:container";
        let expectedTwo = "/tsmatsuzsttest0001/mycontainer/myblob";
        let expectedThree = "/tsmatsuzsttest0001/container\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\nrestype:container";
        assert.deepEqual(myAzureSign.canonicalisedResource(url), expected);
        assert.deepEqual(myAzureSign.canonicalisedResource(urlTwo), expectedTwo);
        assert.deepEqual(myAzureSign.canonicalisedResource(urlThree), expectedThree);
    });
    
    it("produces a full string for signing", function(){
        let date = new Date();
        let testObject = {
            method: "GET",
            headers: {
                "Content-Encoding": "gzip",
                nonstandard: "test",
                Date: date,
                "not-ms-header": "test data",
                "x-ms-version": "2014-02-14"
            },
            protocol: "https:",
            host: "tsmatsuzsttest0001.blob.core.windows.net",
            path: "/mycontainer?restype=container&comp=metadata"
        };
        let expected = "GET\ngzip\n\n\n\n\n" + date + "\n\n\n\n\n\nx-ms-version:2014-02-14\n/tsmatsuzsttest0001/mycontainer\ncomp:metadata\nrestype:container";
        assert.deepEqual(myAzureSign.getFullString(testObject), expected);
    });
});
