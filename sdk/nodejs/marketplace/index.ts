// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./acceptedAgreement";
export * from "./getAcceptedAgreement";
export * from "./getAcceptedAgreements";
export * from "./getCategories";
export * from "./getListing";
export * from "./getListingPackage";
export * from "./getListingPackageAgreements";
export * from "./getListingPackages";
export * from "./getListingTaxes";
export * from "./getListings";
export * from "./getPublication";
export * from "./getPublicationPackage";
export * from "./getPublicationPackages";
export * from "./getPublications";
export * from "./getPublishers";
export * from "./publication";

// Import resources to register:
import { AcceptedAgreement } from "./acceptedAgreement";
import { Publication } from "./publication";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:marketplace/acceptedAgreement:AcceptedAgreement":
                return new AcceptedAgreement(name, <any>undefined, { urn })
            case "oci:marketplace/publication:Publication":
                return new Publication(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "marketplace/acceptedAgreement", _module)
pulumi.runtime.registerResourceModule("oci", "marketplace/publication", _module)
