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
    public sealed class GetListingsListingResult
    {
        /// <summary>
        /// Product categories that the listing belongs to.
        /// </summary>
        public readonly ImmutableArray<string> Categories;
        /// <summary>
        /// The model for upload data for images and icons.
        /// </summary>
        public readonly Outputs.GetListingsListingIconResult Icon;
        /// <summary>
        /// Unique identifier for the publisher.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether to show only featured listings. If this is set to `false` or is omitted, then all listings will be returned.
        /// </summary>
        public readonly bool IsFeatured;
        /// <summary>
        /// In which catalog the listing should exist.
        /// </summary>
        public readonly string ListingType;
        /// <summary>
        /// The name of the listing.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// A filter to return only packages that match the given package type exactly.
        /// </summary>
        public readonly string PackageType;
        public readonly ImmutableArray<string> PricingTypes;
        /// <summary>
        /// Summary details about the publisher of the listing.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingPublisherResult> Publishers;
        /// <summary>
        /// The regions where the listing is eligible to be deployed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingRegionResult> Regions;
        /// <summary>
        /// A short description of the listing.
        /// </summary>
        public readonly string ShortDescription;
        /// <summary>
        /// List of operating systems supported.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListingsListingSupportedOperatingSystemResult> SupportedOperatingSystems;

        [OutputConstructor]
        private GetListingsListingResult(
            ImmutableArray<string> categories,

            Outputs.GetListingsListingIconResult icon,

            string id,

            bool isFeatured,

            string listingType,

            string name,

            string packageType,

            ImmutableArray<string> pricingTypes,

            ImmutableArray<Outputs.GetListingsListingPublisherResult> publishers,

            ImmutableArray<Outputs.GetListingsListingRegionResult> regions,

            string shortDescription,

            ImmutableArray<Outputs.GetListingsListingSupportedOperatingSystemResult> supportedOperatingSystems)
        {
            Categories = categories;
            Icon = icon;
            Id = id;
            IsFeatured = isFeatured;
            ListingType = listingType;
            Name = name;
            PackageType = packageType;
            PricingTypes = pricingTypes;
            Publishers = publishers;
            Regions = regions;
            ShortDescription = shortDescription;
            SupportedOperatingSystems = supportedOperatingSystems;
        }
    }
}
