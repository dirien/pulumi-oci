// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Outputs
{

    [OutputType]
    public sealed class GetCustomTablesCustomTableCollectionItemSavedCustomTableResult
    {
        /// <summary>
        /// The column groupBy key list. example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "tenantId", "tenantName"]`
        /// </summary>
        public readonly ImmutableArray<string> ColumnGroupBies;
        /// <summary>
        /// The compartment depth level.
        /// </summary>
        public readonly double CompartmentDepth;
        /// <summary>
        /// The name of the custom table.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{"namespace":"oracle", "key":"createdBy"]`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTagResult> GroupByTags;
        /// <summary>
        /// The row groupBy key list. example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "tenantId", "tenantName"]`
        /// </summary>
        public readonly ImmutableArray<string> RowGroupBies;
        /// <summary>
        /// The version of the custom table.
        /// </summary>
        public readonly double Version;

        [OutputConstructor]
        private GetCustomTablesCustomTableCollectionItemSavedCustomTableResult(
            ImmutableArray<string> columnGroupBies,

            double compartmentDepth,

            string displayName,

            ImmutableArray<Outputs.GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTagResult> groupByTags,

            ImmutableArray<string> rowGroupBies,

            double version)
        {
            ColumnGroupBies = columnGroupBies;
            CompartmentDepth = compartmentDepth;
            DisplayName = displayName;
            GroupByTags = groupByTags;
            RowGroupBies = rowGroupBies;
            Version = version;
        }
    }
}
