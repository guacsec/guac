assembler/backends
==================

This directory contains implementation for 2 backends for the GraphQL server
side of ["Refactoring the GUAC
Assembler"](https://docs.google.com/document/d/1yZ3-ZcfnRDWgw9uZlPuLmIHS9pNMr3DO_AEbHsDXmN8/edit?usp=sharing)
project.

**Note**: This is still in experimental state and might change in the future!

## Backend definition

- `backends.go`: defines the 2 interfaces needed to create a backend: one that
  contains the implementation for each resolver (to ensure backends implement
  everything) and one empty interface to account for the arguments needed to
  create the backend.

## Backends

- `neo4j/`: Backend based on the Neo4j database
- `testing/`: simple backend with no resolvers implemented. Useful for
  prototyping. Also known as the in-memory backend.
