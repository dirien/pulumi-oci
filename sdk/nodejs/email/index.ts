// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./dkim";
export * from "./emailDomain";
export * from "./getDkim";
export * from "./getDkims";
export * from "./getEmailDomain";
export * from "./getEmailDomains";
export * from "./getSender";
export * from "./getSenders";
export * from "./getSuppression";
export * from "./getSuppressions";
export * from "./sender";
export * from "./suppression";

// Import resources to register:
import { Dkim } from "./dkim";
import { EmailDomain } from "./emailDomain";
import { Sender } from "./sender";
import { Suppression } from "./suppression";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:email/dkim:Dkim":
                return new Dkim(name, <any>undefined, { urn })
            case "oci:email/emailDomain:EmailDomain":
                return new EmailDomain(name, <any>undefined, { urn })
            case "oci:email/sender:Sender":
                return new Sender(name, <any>undefined, { urn })
            case "oci:email/suppression:Suppression":
                return new Suppression(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "email/dkim", _module)
pulumi.runtime.registerResourceModule("oci", "email/emailDomain", _module)
pulumi.runtime.registerResourceModule("oci", "email/sender", _module)
pulumi.runtime.registerResourceModule("oci", "email/suppression", _module)
