# Experimental REST Feature Design Document

***This is a work-in-progress document.***
## Introduction

The Experimental REST service is a new addition to the GUAC project. It aims to provide a RESTful API interface for querying data from GUAC. This interface complements the existing GraphQL interface, providing an enhanced way for users to query the GUAC data.

## Goals

1. **Provide a RESTful API interface**: The primary goal of this feature is to provide a RESTful API interface that provides a simplified response to complex questions.

2. **Support advanced queries**: The REST API contains advanced queries. These queries require complex client-side filtering, type checking, iteration, or path finding using the existing GraphQL interface. This interface contains all that logic in simple REST API.

3. **Ensure compatibility with existing systems**: The REST API should adhere to REST conventions and best practices so that it is intuitive to consumers and is compatible with existing systems and tools that use RESTful APIs.

## Proposed Design

The REST API will be implemented using the Gin web framework in Go. The API will provide endpoints for querying packages, dependencies, and other related data.

### Why Gin?

Gin is a high-performance web framework for Go that provides robust features for building web applications. It is efficient, lean, and fully compatible with the `net/http` library, making it an excellent choice for implementing a REST API. Furthermore, Gin has a large and active community, ensuring it is well-maintained and up-to-date with the latest best practices in web development.

### Why not the standard HTTP router?

While the standard HTTP router in Go is powerful and flexible, it lacks some of the features and conveniences that Gin provides. For instance, Gin provides middleware support, better error handling, and routing capabilities that are more advanced than the standard HTTP router. Gin is known for its fast routing and request handling. It uses a radix tree for routing, which can sometimes be faster than the standard library's regular expression-based routing.

### Endpoints

The following endpoints will be provided:

- `/known/package/*hash`: This endpoint will retrieve information about a known package based on its hash. The response will include details about the package and its neighbors.
- `/known/source/*vcs`: This endpoint will retrieve information about a known source based on its VCS. The response will include details about the source and its neighbors.
- `/known/artifact/*artifact`: This endpoint will retrieve information about a known artifact based on the artifact provided. The response will include details about the artifact and its neighbors.
- `/vuln/*purl`: This endpoint will retrieve information about a vulnerability based on its purl. The response will include details about the vulnerability and its neighbors.

### Data Models

The data returned by the REST API will be structured according to the following models:

- `Neighbors`: This model will represent the neighbors of a package. It will include fields for the neighbor's hash, scorecards, occurrences, and other relevant details.

### Error Handling

The REST API will return appropriate HTTP status codes in case of errors.

### Dependencies

- `graphql`: This library will interact with the GUAC database. It will allow the API to perform advanced queries and retrieve detailed information about packages and their dependencies.

## References

- Experimental-REST issue on GitHub: [https://github.com/guacsec/guac/issues/1326](https://github.com/guacsec/guac/issues/1326)
- Gin web framework: [https://github.com/gin-gonic/gin](https://github.com/gin-gonic/gin)