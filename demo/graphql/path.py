#!/usr/bin/env python3

#
# Copyright 2023 The GUAC Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import json
import os
import sys

from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

# deepID extracts the ID of a GUAC noun, it looks for the deepest nested object
# with an ID
def deepID(node):
    for i in node.values():
        if type(i) is list:
            for v in i:
                try:
                    v['id']
                    return deepID(v)
                except (TypeError, KeyError):
                    pass
        try:
            i['id']
            return deepID(i)
        except (TypeError, KeyError):
            pass
    return node['id']

def isPackageVersion(node):
    try:
        retrieve = (node['namespaces'][0]['names'][0]['versions'][0])
        return True
    except:
        return False

# guacID returns the ID of a GUAC node. For nouns, the deepest ID is the ID,
# for verbs, it is the top level ID.
def guacID(node):
    match node['__typename']:
      case 'Package':
        return deepID(node)
      case 'IsDependency':
        return node['id']
    # TODO support all types

# containsID searches a GUAC node for an ID. This can be used to tell if an ID
# is a parent of the node.
def containsID(node, id):
    try:
        if node['id'] == id:
            return True
    except (TypeError, KeyError):
        return False
    for i in node.values():
        if type(i) is list:
            for v in i:
                if containsID(v, id):
                    return True
        if containsID(i, id):
            return True
    return False

# bfs finds the shortest path fron start to target, while applying filter() to
# only search in certian ways.
def bfs(startID, targetID):
    visited = set([])
    queue = []
    visited.add(startID)
    queue.append({'id': startID, 'path': [ startID ], 'pathNodes': [ nodeQuery(startID) ]})
    while queue:
        node = queue.pop(0)
        ns = neighbors(node['id'])
        for n in ns:
            nodeID = guacID(n)
            if not filter(node['id'], node['pathNodes'][-1], n):
                continue
            if nodeID in visited:
                continue
            newPath = list(node['path'])
            newPath.append(nodeID)
            newNodePath = list(node['pathNodes'])
            newNodePath.append(n)
            if nodeID == targetID:
                return (newPath, newNodePath)
            visited.add(nodeID)
            queue.append({'id': nodeID, 'path': newPath, 'pathNodes': newNodePath})
    return [], []

# filter is used by bfs to decide weather to search a node or not. In this
# implementation we try to find dependency links between packages
def filter(fromID, fromNode, neighbor):
    if neighbor['__typename'] == 'Package':
        # From Package -> Package, only search downwards
        if fromNode['__typename'] == 'Package':
            return isPackageVersion(neighbor)
            return containsID(neighbor, fromID)
        # From other node type -> Package is ok.
        return True
    # Only allow IsDependency where the fromID is in the subject package
    if neighbor['__typename'] == 'IsDependency':
        return containsID(neighbor['package'], fromID)
    # Otherwise don't follow path
    return False

# neighbors is a wrapper around the GetNeighbors operation stored in the
# queries.gql file
def neighbors(id):
    vars = { 'nodeId': id }
    result = client.execute(queries, operation_name='GetNeighbors', variable_values=vars)
    return result['neighbors']

# nodeQuery is a wrapper around the Node operation stored in the
# queries.gql file
def nodeQuery(id):
    vars = { 'nodeId': id }
    result = client.execute(queries, operation_name='Node', variable_values=vars)
    return result['node']

# Main takes two ID args and prints the shortest path between them
def main(args):
    pathIds, pathNodes = bfs(args[0], args[1])
    print(pathIds)
    print(json.dumps(pathNodes, indent=2))

# Open the queries file and store as a global
scriptDir = os.path.dirname(os.path.realpath(__file__))
f = open(os.path.join(scriptDir, 'queries.gql'), 'r')
queriesTxt = f.read()
queries = gql(queriesTxt)
f.close()

# Open the client and store as a global
transport = RequestsHTTPTransport(url='http://localhost:8080/query')
client = Client(transport=transport, fetch_schema_from_transport=True)

main(sys.argv[1:])

transport.close()
