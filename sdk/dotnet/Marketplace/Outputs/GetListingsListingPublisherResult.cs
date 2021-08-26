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
    public sealed class GetListingsListingPublisherResult
    {
        /// <summary>
        /// A description of the screenshot.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Unique identifier for the publisher.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the listing.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetListingsListingPublisherResult(
            string description,

            string id,

            string name)
        {
            Description = description;
            Id = id;
            Name = name;
        }
    }
}