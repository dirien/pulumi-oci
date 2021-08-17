package main

import (
	"github.com/pulumi/pulumi-oci/sdk/v4/go/oci"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		oci.NewIdentityCompartment(ctx, "compartement", &oci.IdentityCompartmentArgs{
			Description: pulumi.String("Test Description"),
			Name:        pulumi.StringPtr("test-pulumi-go"),
		})
		return nil
	})
}
