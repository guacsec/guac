# Ent Backend

This contains the RDMS backend powered by Ent.

## Developing

Adding new nodes:

```shell
go run -mod=mod entgo.io/ent/cmd/ent new --target pkg/assembler/backends/ent/schema <NodeName>
```

Generating the schema:

```shell
go generate pkg/assembler/backends/ent/generate.go
```
