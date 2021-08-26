// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class GetScriptParameterScriptParameterResult
    {
        /// <summary>
        /// If the parameter value is secret and should be kept confidential, then set isSecret to true.
        /// </summary>
        public readonly bool IsSecret;
        /// <summary>
        /// Name of the parameter.
        /// </summary>
        public readonly string ParamName;
        /// <summary>
        /// Value of the parameter.
        /// </summary>
        public readonly string ParamValue;

        [OutputConstructor]
        private GetScriptParameterScriptParameterResult(
            bool isSecret,

            string paramName,

            string paramValue)
        {
            IsSecret = isSecret;
            ParamName = paramName;
            ParamValue = paramValue;
        }
    }
}
