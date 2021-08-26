// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlDbSystemMaintenanceArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The start of the 2 hour maintenance window.
        /// </summary>
        [Input("windowStartTime", required: true)]
        public Input<string> WindowStartTime { get; set; } = null!;

        public MysqlDbSystemMaintenanceArgs()
        {
        }
    }
}
