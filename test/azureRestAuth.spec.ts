// Copyright 2019 Chris Lount
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {AzureSign} from "../src/azureRestAuth";
import * as assert from "assert";

describe("It generates azure shared key authorizaton string", function(){

    before(function(){
        this.myAzureSign = new AzureSign("tsmatsuzsttest0001", "93K17Co74T2lDHk2rA+wmb/avIAS6u6lPnZrk2hyT+9+aov82qNhrcXSNGZCzm9mjd4d75/oxxOr6r1JVpgTLA==");
    });

    it("Produces a canonacolised string from x-ms- header values", function(){
        const testObject = {
            headers: {
                "not-ms-header": "test data",
                "x-ms-version": "2014-02-14",
                "x-ms-date": "Sat, 21   Feb 2015 00:48:38 GMT"
            }
        };
        const expectedString = "x-ms-date:Sat, 21 Feb 2015 00:48:38 GMT\nx-ms-version:2014-02-14\n";
        assert.deepStrictEqual(this.myAzureSign.canonicalisedHeaders(testObject), expectedString);
    });

    it("builds a string from a header object", function(){
        const date = new Date();
        const testObject = {
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
        const expectedString = "GET\ngzip\nen\n\nMD5String\napplication/json\n" + date + "\nTue, 05 Jul 2016 06:48:26 GMT\nitemOne\nitemTwo\nTue, 07 Jul 2016 06:48:26 GMT\ntestRange\n";
        assert.deepStrictEqual(this.myAzureSign.headerString(testObject), expectedString);
    });

    it("returns header number values as a string for signing", function(){
        const testString = 1234;
        const result = this.myAzureSign.trimSpaces(testString);
        assert.deepStrictEqual(typeof result, "string");
        assert.deepStrictEqual(result, "1234");
    });

    it("signs the string", function(){
        const testObject = {
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
        assert.deepStrictEqual(this.myAzureSign.getAuthHeaderValue(testObject), "SharedKey tsmatsuzsttest0001:sGX7uEBy8i9ldZtx8nLDeD3vX3AI/LB/3msK0oL7oMI=");
    });

    it("Produces a canonicalised resource string for accessing the resource", function(){
        const url = {
            protocol: "https:",
            host: "myaccount.blob.core.windows.net",
            path: "/mycontainer?restype=container&comp=metadata"
        };
        const urlTwo = {
            protocol: "https:",
            host: "myaccount-secondary.blob.core.windows.net",
            path: "/mycontainer/myblob"
        };
        const urlThree = {
            protocol: "https:",
            host: "myaccount.blob.core.windows.net",
            path: "/container?restype=container&comp=list&include=snapshots&include=metadata&include=uncommittedblobs"
        };
        const expected = "/tsmatsuzsttest0001/mycontainer\ncomp:metadata\nrestype:container";
        const expectedTwo = "/tsmatsuzsttest0001/mycontainer/myblob";
        const expectedThree = "/tsmatsuzsttest0001/container\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\nrestype:container";
        assert.deepStrictEqual(this.myAzureSign.canonicalisedResource(url), expected);
        assert.deepStrictEqual(this.myAzureSign.canonicalisedResource(urlTwo), expectedTwo);
        assert.deepStrictEqual(this.myAzureSign.canonicalisedResource(urlThree), expectedThree);
    });

    it("produces a full string for signing", function(){
        const date = new Date();
        const testObject = {
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
        const expected = "GET\ngzip\n\n\n\n\n" + date + "\n\n\n\n\n\nx-ms-version:2014-02-14\n/tsmatsuzsttest0001/mycontainer\ncomp:metadata\nrestype:container";
        assert.deepStrictEqual(this.myAzureSign.getFullString(testObject), expected);
    });
});
