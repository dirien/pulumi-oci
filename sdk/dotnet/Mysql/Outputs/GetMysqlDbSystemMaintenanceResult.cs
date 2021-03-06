// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlDbSystemMaintenanceResult
    {
        /// <summary>
        /// The start time of the maintenance window.
        /// </summary>
        public readonly string WindowStartTime;

        [OutputConstructor]
        private GetMysqlDbSystemMaintenanceResult(string windowStartTime)
        {
            WindowStartTime = windowStartTime;
        }
    }
}
