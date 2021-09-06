// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDatabaseRegionalWalletManagement
    {
        /// <summary>
        /// This data source provides details about a specific Autonomous Database Regional Wallet Management resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the Autonomous Database regional wallet details.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testAutonomousDatabaseRegionalWalletManagement = Output.Create(Oci.Database.GetAutonomousDatabaseRegionalWalletManagement.InvokeAsync());
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAutonomousDatabaseRegionalWalletManagementResult> InvokeAsync(InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDatabaseRegionalWalletManagementResult>("oci:database/getAutonomousDatabaseRegionalWalletManagement:getAutonomousDatabaseRegionalWalletManagement", InvokeArgs.Empty, options.WithVersion());
    }


    [OutputType]
    public sealed class GetAutonomousDatabaseRegionalWalletManagementResult
    {
        public readonly string Id;
        public readonly bool ShouldRotate;
        /// <summary>
        /// The current lifecycle state of the Autonomous Database wallet.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the wallet was last rotated.
        /// </summary>
        public readonly string TimeRotated;

        [OutputConstructor]
        private GetAutonomousDatabaseRegionalWalletManagementResult(
            string id,

            bool shouldRotate,

            string state,

            string timeRotated)
        {
            Id = id;
            ShouldRotate = shouldRotate;
            State = state;
            TimeRotated = timeRotated;
        }
    }
}
