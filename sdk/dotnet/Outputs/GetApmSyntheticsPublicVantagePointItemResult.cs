// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetApmSyntheticsPublicVantagePointItemResult
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Geographic summary about a vantage point.
        /// </summary>
        public readonly Outputs.GetApmSyntheticsPublicVantagePointItemGeoResult Geo;
        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetApmSyntheticsPublicVantagePointItemResult(
            string displayName,

            Outputs.GetApmSyntheticsPublicVantagePointItemGeoResult geo,

            string name)
        {
            DisplayName = displayName;
            Geo = geo;
            Name = name;
        }
    }
}