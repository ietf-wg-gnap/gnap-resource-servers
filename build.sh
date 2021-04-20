#!/bin/sh

mkdir -p publish
cp _redirects publish/_redirects
kramdown-rfc2629 -3 draft-ietf-gnap-resource-servers.md > publish/draft-ietf-gnap-resource-servers.xml
xml2rfc --v2v3 publish/draft-ietf-gnap-resource-servers.xml -o publish/draft-ietf-gnap-resource-servers.xml
xml2rfc --text publish/draft-ietf-gnap-resource-servers.xml
xml2rfc --html publish/draft-ietf-gnap-resource-servers.xml
