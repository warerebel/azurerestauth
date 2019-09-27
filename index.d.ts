// Type definitions for azureRestAuth 0.4.0
// Project: azureRestAuth

export class AzureSign {
    constructor(accountName?: string, SASToken?: string);

    account: string[];
    key: Buffer;

    getAuthHeaderValue(request: HttpOptions): string;
}

export interface HttpOptions {
    headers?: {[index: string]: any};
    method: string;
    host: string;
    protocol: string;
    path?: string;
}
