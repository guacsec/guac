# Information on the Experimental guacrest API

## Overview

`guacrest` is a component of the GUAC project that provides a REST API interface to the underlying GUAC GraphQL services. It serves as a more accessible endpoint for clients not using GraphQL directly.

## Creating a REST API Endpoint

To create a new REST API endpoint in `guacrest`, follow these steps:

1. **Define the OpenAPI Specification**: Start by defining your endpoint in the `openapi.yaml` file. This includes specifying the path, request parameters, and response objects. For example, to add a new endpoint for analyzing dependencies:

``` yaml
"/analysis/newEndpoint":
  get:
    summary: Description of the new endpoint
    operationId: newEndpointOperation
    parameters:
      - name: param1
        description: Description of the new endpoint
        in: query
        required: true
        schema:
          type: string
    responses:
      "200":
        description: Successful response
        content:
          application/json:
            schema:
              type: string
      "400":
        $ref: "#/components/responses/BadRequest"
      "500":
        $ref: "#/components/responses/InternalServerError"
      "502":
        $ref: "#/components/responses/BadGateway"
```

2. **Generate Server Code**: Run `make generate` to generate server stubs based on the OpenAPI spec. This will update the `generated` package with new types and handlers.

3. **Implement the Server Logic**: In the `server.go` file, implement the logic for the new endpoint. This involves adding a new method to the `DefaultServer` struct that matches the operation ID specified in the OpenAPI spec.

``` go
func (s *DefaultServer) NewEndpointOperation(ctx context.Context, request gen.NewEndpointOperationRequestObject) (gen.NewEndpointOperationResponseObject, error) {
    // Implement your logic here
    return gen.NewEndpointOperation200JSONResponse("Success message"), nil
}
```

4. **Register the Endpoint**: The generated server code automatically registers the new endpoint. Ensure your server is set up to serve the generated handler.

## Future support

1. **Pagination**: Future enhancements include adding pagination.