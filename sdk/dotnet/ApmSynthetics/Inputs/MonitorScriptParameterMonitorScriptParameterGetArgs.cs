// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class MonitorScriptParameterMonitorScriptParameterGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the parameter.
        /// </summary>
        [Input("paramName")]
        public Input<string>? ParamName { get; set; }

        /// <summary>
        /// (Updatable) Value of the parameter.
        /// </summary>
        [Input("paramValue")]
        public Input<string>? ParamValue { get; set; }

        public MonitorScriptParameterMonitorScriptParameterGetArgs()
        {
        }
    }
}
