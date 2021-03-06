// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetClustersClusterOptionsKubernetesNetworkConfigResult
    {
        /// <summary>
        /// The CIDR block for Kubernetes pods.
        /// </summary>
        public readonly string PodsCidr;
        /// <summary>
        /// The CIDR block for Kubernetes services.
        /// </summary>
        public readonly string ServicesCidr;

        [OutputConstructor]
        private GetClustersClusterOptionsKubernetesNetworkConfigResult(
            string podsCidr,

            string servicesCidr)
        {
            PodsCidr = podsCidr;
            ServicesCidr = servicesCidr;
        }
    }
}
