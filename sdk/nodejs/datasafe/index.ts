// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./dataSafeConfiguration";
export * from "./dataSafePrivateEndpoint";
export * from "./getDataSafeConfiguration";
export * from "./getDataSafePrivateEndpoint";
export * from "./getDataSafePrivateEndpoints";
export * from "./getOnPremConnector";
export * from "./getOnPremConnectors";
export * from "./getTargetDatabase";
export * from "./getTargetDatabases";
export * from "./onPremConnector";
export * from "./targetDatabase";

// Import resources to register:
import { DataSafeConfiguration } from "./dataSafeConfiguration";
import { DataSafePrivateEndpoint } from "./dataSafePrivateEndpoint";
import { OnPremConnector } from "./onPremConnector";
import { TargetDatabase } from "./targetDatabase";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:datasafe/dataSafeConfiguration:DataSafeConfiguration":
                return new DataSafeConfiguration(name, <any>undefined, { urn })
            case "oci:datasafe/dataSafePrivateEndpoint:DataSafePrivateEndpoint":
                return new DataSafePrivateEndpoint(name, <any>undefined, { urn })
            case "oci:datasafe/onPremConnector:OnPremConnector":
                return new OnPremConnector(name, <any>undefined, { urn })
            case "oci:datasafe/targetDatabase:TargetDatabase":
                return new TargetDatabase(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "datasafe/dataSafeConfiguration", _module)
pulumi.runtime.registerResourceModule("oci", "datasafe/dataSafePrivateEndpoint", _module)
pulumi.runtime.registerResourceModule("oci", "datasafe/onPremConnector", _module)
pulumi.runtime.registerResourceModule("oci", "datasafe/targetDatabase", _module)
