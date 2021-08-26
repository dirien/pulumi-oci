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
    public sealed class GetListingRegionCountryResult
    {
        /// <summary>
        /// A code assigned to the item.
        /// </summary>
        public readonly string Code;
        /// <summary>
        /// Text that describes the resource.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetListingRegionCountryResult(
            string code,

            string name)
        {
            Code = code;
            Name = name;
        }
    }
}
