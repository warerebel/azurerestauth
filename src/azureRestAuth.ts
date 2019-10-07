import { createHmac } from "crypto";
import {Agent} from "http";

export interface HttpOptions {
    headers: {[index: string]: string};
    method: string;
    host: string;
    protocol: string;
    path: string;
    agent?: Agent;
    [propName: string]: any;
}

export class AzureSign{
    account: string;
    key: Buffer;
    constructor(account: string, key: string){
        this.account = account;
        this.key = typeof key !== "undefined" ? Buffer.from(key, "base64") : Buffer.from("");
    }
    
    getAuthHeaderValue(request: HttpOptions): string{
        const headerValue = createHmac("sha256", this.key)
            .update(this.getFullString(request))
            .digest("base64");
        return "SharedKey ".concat(this.account,":",headerValue);
    }
    
    getFullString(request: HttpOptions): string{
        const headerString = this.headerString(request);
        const canonHeader = this.canonicalisedHeaders(request);
        const canonResource = this.canonicalisedResource(request);
        const fullString = headerString.concat(canonHeader, canonResource);
        return fullString;
    }
    
    headerString(request: HttpOptions): string{
        let string = "";
        const requestObject = request.headers;
        string += request.method + "\n";
        string += typeof requestObject["Content-Encoding"] !== "undefined" ? requestObject["Content-Encoding"] + "\n" : "\n";
        string += typeof requestObject["Content-Language"] !== "undefined" ? requestObject["Content-Language"] + "\n" : "\n";
        string += typeof requestObject["Content-Length"] !== "undefined" && parseInt(requestObject["Content-Length"]) > 0 ? requestObject["Content-Length"] + "\n" : "\n";
        string += typeof requestObject["Content-MD5"] !== "undefined" ? requestObject["Content-MD5"] + "\n" : "\n";
        string += typeof requestObject["Content-Type"] !== "undefined" ? requestObject["Content-Type"] + "\n" : "\n"; 
        string += typeof requestObject.Date !== "undefined" ? requestObject.Date + "\n" : "\n";
        string += typeof requestObject["If-Modified-Since"] !== "undefined" ? requestObject["If-Modified-Since"] + "\n" : "\n";
        string += typeof requestObject["If-Match"] !== "undefined" ? requestObject["If-Match"] + "\n" : "\n";
        string += typeof requestObject["If-None-Match"] !== "undefined" ? requestObject["If-None-Match"] + "\n" : "\n";
        string += typeof requestObject["If-Unmodified-Since"] !== "undefined" ? requestObject["If-Unmodified-Since"] + "\n" : "\n";
        string += typeof requestObject.Range !== "undefined" ? requestObject.Range + "\n" : "\n";
        
        return string;
    }
    
    canonicalisedHeaders(request: HttpOptions): string{
        const requestObject = request.headers;
        let canonicalString = "";
        const canonicalHeaders = [];
        for (const property in requestObject){
            if(Object.prototype.hasOwnProperty.call(requestObject, property) && property.indexOf("x-ms-") > -1){
                canonicalHeaders.push(property);
                requestObject[property] = this.trimSpaces(requestObject[property]);
            }
        }
        canonicalHeaders.sort();
        const lowerHeaders = canonicalHeaders.map((x) => x.toLowerCase());
        canonicalHeaders.forEach(function(item, index){
            canonicalString += lowerHeaders[index];
            canonicalString += ":";
            canonicalString += requestObject[item];
            canonicalString += "\n";
        });
        
        return canonicalString;
    }
    
    trimSpaces(inString: string): string{
        return typeof inString.replace !== "undefined" ? inString.replace(/\s+/g," ") : inString;
    }
    
    canonicalisedResource(request: HttpOptions): string{
        const requestUrl = new URL(request.protocol.concat("//",request.host, request.path));
        let string = "/";
        string += this.account;
        string += requestUrl.pathname;
        const params: { [index: string]: string[]} = {};
        const paramList: string[] = [];
        requestUrl.searchParams.forEach(function(value, name){
            if(typeof params[name.toLowerCase()] === "undefined")
                params[name.toLowerCase()] = [];
            params[name.toLowerCase()].push(value);
            paramList.push(name.toLowerCase());
        });
        paramList.sort();
        paramList.forEach(function(param){
            if(params[param].length > 0){
                params[param] = params[param].sort();
                const paramString = params[param].join();
                params[param] = [];
                string += "\n" + param + ":" + paramString;
            }
        });
        return string;
    }
}



