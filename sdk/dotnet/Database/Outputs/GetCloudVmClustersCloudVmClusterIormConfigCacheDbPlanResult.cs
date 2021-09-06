// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetCloudVmClustersCloudVmClusterIormConfigCacheDbPlanResult
    {
        public readonly string DbName;
        public readonly string FlashCacheLimit;
        public readonly int Share;

        [OutputConstructor]
        private GetCloudVmClustersCloudVmClusterIormConfigCacheDbPlanResult(
            string dbName,

            string flashCacheLimit,

            int share)
        {
            DbName = dbName;
            FlashCacheLimit = flashCacheLimit;
            Share = share;
        }
    }
}
