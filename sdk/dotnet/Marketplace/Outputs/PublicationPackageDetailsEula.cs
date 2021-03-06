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
    public sealed class PublicationPackageDetailsEula
    {
        /// <summary>
        /// the specified eula's type
        /// </summary>
        public readonly string EulaType;
        /// <summary>
        /// text of the eula
        /// </summary>
        public readonly string? LicenseText;

        [OutputConstructor]
        private PublicationPackageDetailsEula(
            string eulaType,

            string? licenseText)
        {
            EulaType = eulaType;
            LicenseText = licenseText;
        }
    }
}
