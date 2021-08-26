// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class MonitorConfigurationVerifyTextArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Verification text in the response.
        /// </summary>
        [Input("text")]
        public Input<string>? Text { get; set; }

        public MonitorConfigurationVerifyTextArgs()
        {
        }
    }
}
