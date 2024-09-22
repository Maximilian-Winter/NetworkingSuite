#!/bin/bash

SERVER="http://localhost:80"

echo "Testing GET request:"
curl -v "${SERVER}/"

echo "\nTesting POST request:"
curl -v -X POST -d "key=value" "${SERVER}/post"

echo "\nTesting PUT request:"
curl -v -X PUT -d "updated=data" "${SERVER}/put"

echo "\nTesting DELETE request:"
curl -v -X DELETE "${SERVER}/delete"

echo "\nTesting OPTIONS request:"
curl -v -X OPTIONS "${SERVER}/"

echo "\nTesting HEAD request:"
curl -v -I "${SERVER}/"

echo "\nTesting persistent connection:"
curl -v -H "Connection: keep-alive" "${SERVER}/"

echo "\nTesting chunked transfer encoding:"
curl -v -H "Transfer-Encoding: chunked" -d "This is chunked data" "${SERVER}/chunked"