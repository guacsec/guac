# REST API Documentation 

## The guacrest is currently an EXPERIMENTAL Feature!

## Implementation:

* Using gin-gonic gin framework for building REST API

## Available HTTP Methods:

* **GET** pURL - Fetches a known item using a given pURL. The pURL is a mandatory parameter. 
  * **Success Response**: 
    * If the pURL is valid and the known item is found, the server responds with HTTP status code `200` and includes the known item in the response body.
  * **Error Responses**: 
    * If the pURL is invalid, the server responds with HTTP status code `400` (Bad Request).
    * If the known item is not found for the provided pURL, the server responds with HTTP status code `404` (Not Found).
    * For any other server errors, the server responds with HTTP status code `500` (Internal Server Error).

## Endpoints:

- `/known/package/*hash`
- `/known/source/*vcs`
- `/known/artifact/*artifact`
- `/vuln/*purl`
- `/bad`
