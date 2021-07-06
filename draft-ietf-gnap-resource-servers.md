---
title: 'Grant Negotiation and Authorization Protocol Resource Server Connections'
docname: draft-ietf-gnap-resource-servers-latest
category: std

ipr: trust200902
area: Security
workgroup: GNAP
keyword: Internet-Draft

stand_alone: yes
pi: [toc, tocindent, sortrefs, symrefs, strict, compact, comments, inline, docmapping]

author:
  - ins: J. Richer
    name: Justin Richer
    organization: Bespoke Engineering
    email: ietf@justin.richer.org
    uri: https://bspk.io/
    role: editor

  - ins: A. Parecki
    name: Aaron Parecki
    email: aaron@parecki.com
    organization: Okta
    uri: https://aaronparecki.com

  - ins: F. Imbault
    name: Fabien Imbault
    organization: acert.io
    email: fabien.imbault@acert.io
    uri: https://acert.io/

normative:
    BCP195:
       target: 'https://www.rfc-editor.org/info/bcp195'
       title: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
       date: May 2015
       author:
         - 
           ins: Y. Sheffer
         - 
           ins: R. Holz
         -
           ins: P. Saint-Andre
    RFC2119:
    RFC7519:
    RFC8174:
    RFC8259:
    I-D.ietf-gnap-core-protocol:

--- abstract

GNAP defines a mechanism for delegating authorization to a
piece of software, and conveying that delegation to the software.
This extension defines methods for resource servers (RS) to communicate
with authorization servers (AS) in an interoperable fashion.

--- middle

# Introduction

The core GNAP protocol does not define any one specific mechanism
for the resource server (RS) to communicate with the authorization
server (AS), allowing the connection between these components
to be solved orthogonally to the core protocol's concerns. For example, 
the RS and AS roles could be fulfilled by the same piece of software with
common storage, obviating the need for any connecting protocol. However,
it is often desirable to have the RS and AS communicate at runtime
for a variety of purposes, including allowing the RS to validate and
understand the rights and privileges associated with a grant of 
access represented by an access token issued by the AS, or negotiating
the capabilities of either party. These types of 
connections are particularly useful for connecting an AS and RS from
different vendors, allowing interoperable distributed deployments
of GNAP-protected systems.

This specification defines several means for a RS and AS to
communicate these aspects with each other, including structured
access tokens and RS-facing APIs. This specification also discusses
methods for an RS to derive a downstream token for calling another
chained RS.

The means of the authorization server issuing
the access token to the client instance and the means of the client instance
presenting the access token to the resource server are the subject of the 
GNAP core protocol specification {{I-D.ietf-gnap-core-protocol}}.

## Terminology

{::boilerplate bcp14}

This document contains non-normative examples of partial and complete HTTP messages, JSON structures, URLs, query components, keys, and other elements. Some examples use a single trailing backslash '\' to indicate line wrapping for long values, as per {{!RFC8792}}. The `\` character and leading spaces on wrapped lines are not part of the value.

# Access Token Formats {#structure}

When the AS issues an access token for use at an RS, the RS
needs to have some means of understanding what the access token is for
in order to determine how to respond to the request. The core GNAP
protocol makes no assumptions or demands on the format or contents
of the access token, and in fact the token format and contents are opaque
to the client instance. However, such token formats can be the topic of agreements
between the AS and RS.

Self-contained structured token formats allow for the conveyance
of information between the AS and RS without requiring the RS to
call the AS at runtime as described in {{introspection}}. Structured tokens
can also be used in combination with introspection, allowing the token itself
to carry one class of information and the introspection response to carry
another.

Some token formats, such as Macaroons and Biscuits, allow for
the RS to derive sub-tokens without having to call the AS
as described in {{token-chaining}}.

The supported token formats can be communicated dynamically at runtime
between the AS and RS in several places. 

- The AS can declare its supported token formats as part of RS-facing discovery {{discovery}}
- The RS can require a specific token format be used to access a registered resource set {{rs-register-resource-handle}}
- The AS can return the token's format in an introspection response {{introspection}}

In all places where the token format is listed explicitly, it MUST be one of the registered
values in the GNAP Token Formats Registry {{iana-token-format}}.

# Resource-Server-Facing API

To facilitate runtime and dynamic connections, the AS can offer an
RS-Facing API consisting of one or more of the following optional
pieces.

- Discovery
- Introspection
- Token chaining
- Resource reference registration

## RS-facing AS Discovery {#discovery}

A GNAP AS offering RS-facing services can publish its features on
a well-known discovery document using the URL `.well-known/gnap-as-rs`.

This endpoint contains a JSON document {{RFC8259}} consisting of a single JSON
object with any combination of the following optional fields:

introspection_endpoint:
: The URL of the endpoint offering introspection. {{introspection}}

token_formats_supported:
: A list of token formats supported by this AS. The values in this list
    MUST be registered in the GNAP Token Format Registry. {{iana-token-format}}

resource_registration_endpoint:
: The URL of the endpoint offering resource registration. {{rs-register-resource-handle}}

grant_endpoint:
: The grant endpoint of the GNAP AS.

## Protecting RS requests to the AS {#authentication}

Unless otherwise specified, the RS protects its calls to the AS using any of the signature
methods defined by GNAP. This signing method MUST cover all of the appropriate
portions of the HTTP request message, including any body elements, tokens, or
headers required for functionality.

The AS MAY require an RS to pre-register its keys
or could alternatively allow calls from arbitrary keys, in a trust-on-first-use
model. The RS MAY present its keys by reference or by value in
the same fashion as a client instance calling the AS in the core protocol
of GNAP {{I-D.ietf-gnap-core-protocol}}.

## Token Introspection {#introspection}

The AS issues access tokens representing a set of delegated access rights
to be used at one or more RSs. The AS can offer an introspection service
to allow an RS to validate that a given access token:

 - has been issued by the AS
 - has not expired
 - has not been revoked
 - is appropriate for the RS identified in the call

When the RS receives an access token, it can call the introspection
endpoint at the AS to get token information. 
\[\[ [See issue #115](https://github.com/ietf-wg-gnap/gnap-core-protocol/issues/115) \]\]

~~~
+--------+       +------+       +------+
| Client |--(1)->|  RS  |       |  AS  |
|Instance|       |      |--(2)->|      |
|        |       |      |       |      |
|        |       |      |<-(3)--|      |
|        |       |      |       +------+
|        |<-(4)--|      |               
+--------+       +------+               
~~~

1. The client instance calls the RS with its access token.

2. The RS introspects the access token value at the AS.
    The RS signs the request with its own key (not the client instance's
    key or the token's key).

3. The AS validates the access token value and the Resource Server's request
    and returns the introspection response for the token.

4. The RS fulfills the request from the client instance.

The RS signs the request with its own key and sends the access
token as the body of the request.

~~~
POST /introspect HTTP/1.1
Host: server.example.com
Content-Type: application/json
Detached-JWS: ejy0...

{
    "access_token": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
    "proof": "httpsig",
    "resource_server": "7C7C4AZ9KHRS6X63AJAO"
}
~~~



The AS responds with a data structure describing the token's
current state and any information the RS would need to validate the
token's presentation, such as its intended proofing mechanism and key
material. The response MAY include any fields defined in an access
token response.

~~~
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
    "active": true,
    "access": [
        "dolphin-metadata", "some other thing"
    ],
    "key": {
        "proof": "httpsig",
        "jwk": {
                "kty": "RSA",
                "e": "AQAB",
                "kid": "xyz-1",
                "alg": "RS256",
                "n": "kOB5rR4Jv0GMeL...."
        }
    }
}
~~~

## Registering a Resource Handle {#rs-register-resource-handle}

If the RS needs to, it can post a set of resources as described in the Resource Access Rights section of 
{{I-D.ietf-gnap-core-protocol}} to the AS's resource registration endpoint.

The RS MUST identify itself with its own key and sign the
request.

~~~
POST /resource HTTP/1.1
Host: server.example.com
Content-Type: application/json
Detached-JWS: ejy0...

{
    "access": [
        {
            "actions": [
                "read",
                "write",
                "dolphin"
            ],
            "locations": [
                "https://server.example.net/",
                "https://resource.local/other"
            ],
            "datatypes": [
                "metadata",
                "images"
            ]
        },
        "dolphin-metadata"
    ],
    "resource_server": "7C7C4AZ9KHRS6X63AJAO"

}
~~~



The AS responds with a handle appropriate to represent the
resources list that the RS presented.

~~~
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
    "resource_handle": "FWWIKYBQ6U56NL1"
}
~~~



The RS MAY make this handle available as part of a 
discovery response as described in {{I-D.ietf-gnap-core-protocol}} or as
documentation to developers.

\[\[ [See issue #117](https://github.com/ietf-wg-gnap/gnap-core-protocol/issues/117) \]\]



# Deriving a downstream token {#token-chaining}

Some architectures require an RS to act as a client instance and use a derived access
token for a secondary RS. Since the RS is not the same entity that made the initial grant
request, the RS is not capable of referencing or modifying the existing grant. As such, 
the RS needs to request or generate a new token access token for its use at the secondary RS.
This internal secondary token is issued in the context of the incoming access token.

While it is possible to use a [token format](#structure) that allows for the
RS to generate its own secondary token,
the AS can allow the RS to request this secondary access token using the same
process used by the original client instance to request the primary access token. Since the
RS is acting as its own client instance from the perspective of GNAP, this process
uses the same grant endpoint, request structure, and response structure as a client
instance's request.

~~~
+--------+       +-------+       +------+       +-------+
| Client |--(1)->|  RS1  |       |  AS  |       |  RS2  |
|Instance|       |       |--(2)->|      |       |       |
|        |       |       |<-(3)--|      |       |       |
|        |       |       |       +------+       |       |
|        |       |       |                      |       |
|        |       |       |-----------(4)------->|       |
|        |       |       |<----------(5)--------|       |
|        |<-(6)--|       |                      |       |
+--------+       +-------+                      +-------+
~~~

1. The client instance calls RS1 with an access token.

2. RS1 presents that token to the AS to get a derived token
    for use at RS2. RS1 indicates that it has no ability
    to interact with the RO. Note that
    RS1 signs its request with its own key, not the token's
    key or the client instance's key.

3. The AS returns a derived token to RS1 for use at RS2.

4. RS1 calls RS2 with the token from (3).

5. RS2 fulfills the call from RS1.

6. RS1 fulfills the call from the original client instance.


If the RS needs to derive a token from one presented to it, it can
request one from the AS by making a token request as described in
{{I-D.ietf-gnap-core-protocol}} and presenting the existing access token's
value in the "existing_access_token" field.

Since the RS is acting as a client instance, 
the RS MUST identify itself with its own key in the `client` field and sign the
request just as any client instance would.

\[\[ [See issue #116](https://github.com/ietf-wg-gnap/gnap-core-protocol/issues/116) \]\]

~~~
POST /tx HTTP/1.1
Host: server.example.com
Content-Type: application/json
Detached-JWS: ejy0...

{
    "access_token": {
        "access": [
            {
                "actions": [
                    "read",
                    "write",
                    "dolphin"
                ],
                "locations": [
                    "https://server.example.net/",
                    "https://resource.local/other"
                ],
                "datatypes": [
                    "metadata",
                    "images"
                ]
            },
            "dolphin-metadata"
        ]
    },
    "client": "7C7C4AZ9KHRS6X63AJAO",
    "existing_access_token": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0"
}
~~~

The AS responds with a token for the downstream RS2 as described in 
{{I-D.ietf-gnap-core-protocol}}. The downstream RS2 could
repeat this process as necessary for calling further RS's.


# Acknowledgements {#Acknowledgements}

(TODO: the ACK section should probably be split between the documents)

# IANA Considerations {#IANA}

\[\[ TBD: There are a lot of items in the document that are expandable
through the use of value registries. \]\]

## GNAP Token Format Registry {#iana-token-format}

This specification establishes the GNAP Token Format Registry to define token formats.

### Registry Template

### Initial Registry Contents 

The table below contains the initial contents of the GNAP Token Format Registry.

|Name|Status|Description|Reference|
|--- |--- |--- |--- |
|`jwt-signed`|Active   | JSON Web Token, signed with JWS | {{RFC7519}} |
|`jwt-encrypted`|Active   | JSON Web Token, encrypted with JWE | {{RFC7519}} |
|`macaroon`|Active   | Macaroon |  |
|`biscuit`|Active   | Biscuit |  |
|`zcap`|Active   | ZCAP |  |
{: title="Initial contents of the GNAP Token Format Registry." }

# Security Considerations {#Security}

\[\[ TBD: There are a lot of security considerations to add. \]\]

All requests have to be over TLS or equivalent as per {{BCP195}}. Many handles act as
shared secrets, though they can be combined with a requirement to
provide proof of a key as well.


# Privacy Considerations {#Privacy}

\[\[ TBD: There are a lot of privacy considerations to add. \]\]

When introspection is used, the AS is made aware of a particular token being used at a particular AS, and the 
AS would not otherwise have insight into this.

When the client instance receives information about the protecting AS from an RS, this can be used to
derive information about the resources being protected without releasing the resources themselves.

--- back
   
# Document History {#history}

- Since -00
    - Added access token format registry.
    - Moved client-facing RS response back to GNAP core document.

- -00 
    - Extracted resource server section.

