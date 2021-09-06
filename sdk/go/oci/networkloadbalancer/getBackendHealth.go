// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package networkloadbalancer

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Backend Health resource in Oracle Cloud Infrastructure Network Load Balancer service.
//
// Retrieves the current health status of the specified backend server.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/networkloadbalancer"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := networkloadbalancer.GetBackendHealth(ctx, &networkloadbalancer.GetBackendHealthArgs{
// 			BackendName:           oci_network_load_balancer_backend.Test_backend.Name,
// 			BackendSetName:        oci_network_load_balancer_backend_set.Test_backend_set.Name,
// 			NetworkLoadBalancerId: oci_network_load_balancer_network_load_balancer.Test_network_load_balancer.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetBackendHealth(ctx *pulumi.Context, args *GetBackendHealthArgs, opts ...pulumi.InvokeOption) (*GetBackendHealthResult, error) {
	var rv GetBackendHealthResult
	err := ctx.Invoke("oci:networkloadbalancer/getBackendHealth:getBackendHealth", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBackendHealth.
type GetBackendHealthArgs struct {
	// The name of the backend server for which to retrieve the health status, specified as <ip>:<port> or as <ip> <OCID>:<port>.  Example: `10.0.0.3:8080` or `ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:8080`
	BackendName string `pulumi:"backendName"`
	// The name of the backend set associated with the backend server for which to retrieve the health status.  Example: `exampleBackendSet`
	BackendSetName string `pulumi:"backendSetName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
}

// A collection of values returned by getBackendHealth.
type GetBackendHealthResult struct {
	BackendName    string `pulumi:"backendName"`
	BackendSetName string `pulumi:"backendSetName"`
	// A list of the most recent health check results returned for the specified backend server.
	HealthCheckResults []GetBackendHealthHealthCheckResult `pulumi:"healthCheckResults"`
	// The provider-assigned unique ID for this managed resource.
	Id                    string `pulumi:"id"`
	NetworkLoadBalancerId string `pulumi:"networkLoadBalancerId"`
	// The general health status of the specified backend server.
	// *   **OK:**  All health check probes return `OK`
	// *   **WARNING:** At least one of the health check probes does not return `OK`
	// *   **CRITICAL:** None of the health check probes return `OK`. *
	// *   **UNKNOWN:** One of the health checks probes return `UNKNOWN`,
	// *   or the system is unable to retrieve metrics at this time.
	Status string `pulumi:"status"`
}
