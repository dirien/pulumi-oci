// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace.Outputs
{

    [OutputType]
    public sealed class GetPublicationsPublicationPackageDetailsEulaResult
    {
        public readonly string EulaType;
        public readonly string LicenseText;

        [OutputConstructor]
        private GetPublicationsPublicationPackageDetailsEulaResult(
            string eulaType,

            string licenseText)
        {
            EulaType = eulaType;
            LicenseText = licenseText;
        }
    }
}