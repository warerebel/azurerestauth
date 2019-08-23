const crypto = require("crypto");

class azureSign{
    
    constructor(account, key){
        this.account = account;
        this.key = typeof key !== "undefined" ? Buffer.from(key, "base64") : Buffer.from("");
    }
    
    getAuthHeaderValue(request){
        const headerValue = crypto.createHmac("sha256", this.key)
            .update(this.getFullString(request))
            .digest("base64");
        return "SharedKey ".concat(this.account,":",headerValue);
    }
    
    getFullString(request){
        let headerString = this.headerString(request);
        let canonHeader = this.canonicalisedHeaders(request.headers);
        let canonResource = this.canonicalisedResource(request);
        let fullString = headerString.concat(canonHeader, canonResource);
        return fullString;
    }
    
    headerString(request){
        let string = "";
        let requestObject = request.headers;
        string += request.method + "\n";
        string += typeof requestObject["Content-Encoding"] !== "undefined" ? requestObject["Content-Encoding"] + "\n" : "\n";
        string += typeof requestObject["Content-Language"] !== "undefined" ? requestObject["Content-Language"] + "\n" : "\n";
        string += typeof requestObject["Content-Length"] !== "undefined" && requestObject["Content-Length"] > 0 ? requestObject["Content-Length"] + "\n" : "\n";
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
    
    canonicalisedHeaders(requestObject){
        let canonicalString = "";
        let canonicalHeaders = [];
        for (let property in requestObject){
            if(Object.prototype.hasOwnProperty.call(requestObject, property) && property.indexOf("x-ms-") > -1){
                canonicalHeaders.push(property);
                requestObject[property] = this.trimSpaces(requestObject[property]);
            }
        }
        canonicalHeaders.sort();
        let lowerHeaders = canonicalHeaders.map((x) => x.toLowerCase());
        canonicalHeaders.forEach(function(item, index){
            canonicalString += lowerHeaders[index];
            canonicalString += ":";
            canonicalString += requestObject[item];
            canonicalString += "\n";
        });
        
        return canonicalString;
    }
    
    trimSpaces(inString){
        return typeof inString.replace !== "undefined" ? inString.replace(/\s+/g," ") : inString;
    }
    
    canonicalisedResource(request){
        const requestUrl = new URL(request.protocol.concat("//",request.host, request.path));
        let string = "/";
        string += this.account;
        string += requestUrl.pathname;
        let params = {};
        let paramList = [];
        requestUrl.searchParams.forEach(function(value, name){
            if(typeof params[name.toLowerCase()] === "undefined")
                params[name.toLowerCase()] = [];
            params[name.toLowerCase()].push(value);
            paramList.push(name.toLowerCase());
        });
        paramList.sort();
        paramList.forEach(function(param){
            if(typeof params[param].sort !== "undefined"){
                params[param] = params[param].sort();
                params[param] = params[param].join();
                string += "\n" + param + ":" + params[param];
            }
        });
        return string;
    }
}

module.exports = azureSign;
