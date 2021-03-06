// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./customTable";
export * from "./getConfiguration";
export * from "./getCustomTable";
export * from "./getCustomTables";
export * from "./getQueries";
export * from "./getQuery";
export * from "./query";
export * from "./usage";

// Import resources to register:
import { CustomTable } from "./customTable";
import { Query } from "./query";
import { Usage } from "./usage";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:meteringcomputation/customTable:CustomTable":
                return new CustomTable(name, <any>undefined, { urn })
            case "oci:meteringcomputation/query:Query":
                return new Query(name, <any>undefined, { urn })
            case "oci:meteringcomputation/usage:Usage":
                return new Usage(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "meteringcomputation/customTable", _module)
pulumi.runtime.registerResourceModule("oci", "meteringcomputation/query", _module)
pulumi.runtime.registerResourceModule("oci", "meteringcomputation/usage", _module)
