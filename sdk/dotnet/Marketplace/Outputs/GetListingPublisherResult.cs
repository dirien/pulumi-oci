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
    public sealed class GetListingPublisherResult
    {
        /// <summary>
        /// The email address of the publisher.
        /// </summary>
        public readonly string ContactEmail;
        /// <summary>
        /// The phone number of the publisher.
        /// </summary>
        public readonly string ContactPhone;
        /// <summary>
        /// A description of the screenshot.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The address of the publisher's headquarters.
        /// </summary>
        public readonly string HqAddress;
        /// <summary>
        /// Unique identifier for the publisher.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Reference links.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingPublisherLinkResult> Links;
        /// <summary>
        /// The model for upload data for images and icons.
        /// </summary>
        public readonly Outputs.GetListingPublisherLogoResult Logo;
        /// <summary>
        /// Text that describes the resource.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The publisher's website.
        /// </summary>
        public readonly string WebsiteUrl;
        /// <summary>
        /// The year the publisher's company or organization was founded.
        /// </summary>
        public readonly string YearFounded;

        [OutputConstructor]
        private GetListingPublisherResult(
            string contactEmail,

            string contactPhone,

            string description,

            string hqAddress,

            string id,

            ImmutableArray<Outputs.GetListingPublisherLinkResult> links,

            Outputs.GetListingPublisherLogoResult logo,

            string name,

            string websiteUrl,

            string yearFounded)
        {
            ContactEmail = contactEmail;
            ContactPhone = contactPhone;
            Description = description;
            HqAddress = hqAddress;
            Id = id;
            Links = links;
            Logo = logo;
            Name = name;
            WebsiteUrl = websiteUrl;
            YearFounded = yearFounded;
        }
    }
}
