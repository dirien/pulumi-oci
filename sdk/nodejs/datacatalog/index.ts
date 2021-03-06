// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./catalog";
export * from "./catalogPrivateEndpoint";
export * from "./connection";
export * from "./dataAsset";
export * from "./getCatalog";
export * from "./getCatalogPrivateEndpoint";
export * from "./getCatalogPrivateEndpoints";
export * from "./getCatalogType";
export * from "./getCatalogTypes";
export * from "./getCatalogs";
export * from "./getConnection";
export * from "./getConnections";
export * from "./getDataAsset";
export * from "./getDataAssets";

// Import resources to register:
import { Catalog } from "./catalog";
import { CatalogPrivateEndpoint } from "./catalogPrivateEndpoint";
import { Connection } from "./connection";
import { DataAsset } from "./dataAsset";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:datacatalog/catalog:Catalog":
                return new Catalog(name, <any>undefined, { urn })
            case "oci:datacatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint":
                return new CatalogPrivateEndpoint(name, <any>undefined, { urn })
            case "oci:datacatalog/connection:Connection":
                return new Connection(name, <any>undefined, { urn })
            case "oci:datacatalog/dataAsset:DataAsset":
                return new DataAsset(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "datacatalog/catalog", _module)
pulumi.runtime.registerResourceModule("oci", "datacatalog/catalogPrivateEndpoint", _module)
pulumi.runtime.registerResourceModule("oci", "datacatalog/connection", _module)
pulumi.runtime.registerResourceModule("oci", "datacatalog/dataAsset", _module)
