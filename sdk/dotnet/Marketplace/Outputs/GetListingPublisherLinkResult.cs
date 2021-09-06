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
    public sealed class GetListingPublisherLinkResult
    {
        /// <summary>
        /// The anchor tag.
        /// </summary>
        public readonly string Href;
        /// <summary>
        /// Reference links to the previous page, next page, and other pages.
        /// </summary>
        public readonly string Rel;

        [OutputConstructor]
        private GetListingPublisherLinkResult(
            string href,

            string rel)
        {
            Href = href;
            Rel = rel;
        }
    }
}
