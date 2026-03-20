---
title: "OAuth 2.0 Extension: Dynamic On-Behalf-Of Authorization for Delegated Actors"
abbrev: "OAuth 2.0 Dynamic On-Behalf-Of Delegation"
category: info

docname: draft-oauth-dynamic-on-behalf-of-delegation-01
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - secondary-actor
 - dynamic-delegation
 - authorization
 - actor
 - obo
 - autonomous-entity
 - ai-agent
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "shashimalcse/oauth-ai-agents"

author:
 -
    fullname: Thilina Shashimal Senarath
    organization: WSO2
    email: thilinasenarath97@gmail.com
 -
    fullname: Ayesha Dissanayaka
    organization: WSO2
    email: ayshsandu@gmail.com

--- abstract

This specification extends the OAuth 2.0 Authorization Framework {{RFC6749}} to enable dynamic delegation of authority from a human user (the Granting User) to an autonomous software entity (the Delegated Actor) through an OAuth 2.0-mediated flow. A Delegated Actor is any software entity -- such as an AI agent, an automated script, a background service, or a robotic process -- that performs actions on behalf of a user at protected resources.

The specification introduces the `requested_actor` parameter to identify the Delegated Actor for which delegation is requested, and the `actor_token` parameter to cryptographically authenticate the Delegated Actor during a user consented delegation flow. The resulting access token carries structured claims documenting the full delegation chain from the Granting User through the Client to the Delegated Actor. The specification supports Dynamic Consent, enabling the authorization flow to be triggered by a resource server challenge so that consent is obtained in real time when access is attempted, and authorization delegation is just-in-time.

The specification uses Pushed Authorization Requests (PAR) {{RFC9126}} as the authorization initiation mechanism, providing request integrity and upfront actor validation through server-to-server parameter submission. Applicability to Client-Initiated Backchannel Authentication (CIBA) {{OpenID.CIBA}} for ambient use cases and to the standard OAuth 2.0 Authorization Code Grant {{RFC6749}} for low-complexity deployments is described in the appendices.

--- middle

# 1. Introduction

Modern systems increasingly rely on autonomous software entities -- AI agents, automated scripts, background services, robotic process automation (RPA) bots, and other programmatic actors -- that perform tasks on behalf of human users. These entities, referred to in this specification as "Delegated Actors," frequently require access to protected resources governed by OAuth 2.0. The core challenge is the dynamic delegation of authority: enabling a human user (the "Granting User") to securely authorize a Delegated Actor just-in-time to act on their behalf, with fine-grained, auditable, and revocable control.

Standard OAuth 2.0 flows, such as the Authorization Code Grant and the Client Credentials Grant {{RFC6749}}, do not fully address the complexities of delegating authority to an autonomous entity that is distinct from a traditional client application. They lack specific mechanisms to (a) obtain explicit, informed user consent targeted at a particular Delegated Actor, (b) authenticate the Delegated Actor as a distinct identity during the token exchange, or (c) produce access tokens that unambiguously document the delegation chain.

The OAuth 2.0 Token Exchange specification {{RFC8693}} provides a framework for exchanging tokens and introduces the `act` claim to represent delegation chains. However, it is primarily designed for server-to-server communication. It does not natively support obtaining explicit user consent for a Delegated Actor through a human-in-the-loop channel (such as the authorization endpoint or CIBA endpoint), nor does it define how to acquire the initial subject token. This specification builds upon the delegation semantics and the `act` claim of {{RFC8693}} while addressing these gaps.

To address these limitations, this specification extends Pushed Authorization Requests (PAR) {{RFC9126}} to enable dynamic, user-consented, and auditable authorization delegation to Delegated Actors. It introduces the following key enhancements:

1. The `requested_actor` parameter at the PAR endpoint, allowing the Client to specify the Delegated Actor for which delegation is requested.

2. The `actor_token` parameter at both the PAR and token endpoints, enabling the Delegated Actor to cryptographically identify and authenticate itself during authorization initiation and when exchanging a user-approved authorization code for an access token.

3. Upfront Actor Validation via PAR, allowing the Client to submit the `actor_token` during initiation so the Authorization Server can validate the Delegated Actor's identity before prompting the Granting User for consent.

4. A Dynamic Consent mechanism, wherein the authorization flow can be initiated or re-initiated by a resource server challenge, enabling real-time "human-in-the-loop" consent acquisition when the Delegated Actor encounters an access barrier.

5. Structured claims in the resulting access token (following {{RFC9068}}), capturing the identities of the Granting User, the Delegated Actor, and the Client for transparency, auditability, and downstream policy enforcement.

6. Defined error codes for delegation-specific failure modes, including scenarios where consent is denied or where the Delegated Actor's identity does not match the consented delegation.

This approach builds on existing OAuth 2.0 infrastructure and is designed to be technology-agnostic: while AI agents are a prominent use case, the protocol applies equally to any automated system, script, or sub-process that must act on behalf of a human user. The same delegation parameters and semantics defined for PAR are also applicable to Client-Initiated Backchannel Authentication (CIBA) {{OpenID.CIBA}} for ambient use cases (see {{ciba-appendix}}) and to the standard OAuth 2.0 Authorization Code Grant {{RFC6749}} for low-complexity or legacy deployments (see {{direct-appendix}}).

Although this specification uses the term "Delegated Actor" to refer primarily to autonomous software entities, the on-behalf-of delegation model is equally applicable to scenarios where a human user acts on behalf of another human user. For example, an IT support technician who needs to access an employee's account settings to resolve a help-desk ticket can be modeled as a Delegated Actor: the employee (Granting User) authorizes the technician (Delegated Actor) through the Client's delegation flow. In such cases, the CIBA mode ({{ciba-appendix}}) is particularly well-suited, as the employee can approve the delegation request out-of-band -- via a push notification or authentication app -- without needing to be co-present with the technician. The `actor_token` identifies the human actor (the technician), and the resulting access token carries the same structured `act` claim, providing a clear audit trail of who acted on whose behalf.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# 2. Terminology

This specification uses the following terms:

Delegated Actor:
: An autonomous software entity that acts on behalf of a Granting User at protected resources. A Delegated Actor is distinct from the client application; it is the downstream entity to which authority is ultimately delegated. Examples include AI agents, automated scripts, robotic process automation (RPA) bots, background data-processing services, and financial rebalancing algorithms. A Delegated Actor MUST possess a unique, stable identifier and MUST be capable of authenticating itself to the Authorization Server via an Actor Token.

Granting User:
: The human resource owner who explicitly authorizes a Delegated Actor to access their protected resources. The Granting User provides informed consent through the Authorization Server's consent interface, and this consent is bound to a specific Delegated Actor, Client, and set of permissions. This is the "resource owner" as defined in OAuth 2.0 {{RFC6749}}.

Client:
: An application registered as an OAuth 2.0 client that initiates the authorization flow and facilitates the delegation mechanics between the Granting User, the Delegated Actor, and the Authorization Server. The Client acts as an intermediary: it constructs authorization requests on behalf of the Delegated Actor and relays authorization codes and tokens. Because this specification REQUIRES the Delegated Actor to authenticate itself via the `actor_token` at the token endpoint, the Client MAY be a public client (as defined in Section 2.1 of {{RFC6749}}); the Delegated Actor's authentication provides the cryptographic proof of identity that would otherwise be expected from a confidential client. A Client MAY be a standalone application, a sub-component of the Delegated Actor (e.g., a "Tool" or "Plugin" invoked by an AI Orchestrator), or a platform hosting the Delegated Actor.

Dynamic Consent:
: A consent model in which the Granting User's authorization is obtained or refreshed in real time, at the moment a Delegated Actor encounters an access barrier. Unlike static, upfront consent, Dynamic Consent supports a "human-in-the-loop" pattern: the Delegated Actor's flow is interrupted, consent is solicited from the Granting User via the Authorization Server, and the flow resumes once consent is granted. Dynamic Consent MAY be triggered by a resource server challenge (HTTP 401 or 403), or proactively by the Client when a new delegation scope is required.

Authorization Server:
: The server that authenticates the Granting User, obtains their consent for delegation to a specific Delegated Actor, and issues access tokens. The Authorization Server MUST be capable of recognizing Delegated Actor identifiers and binding authorization codes to the tuple of (Granting User, Client, Delegated Actor).

Resource Server:
: The server hosting the protected resources, capable of accepting and validating access tokens. A Resource Server MAY challenge a Client or Delegated Actor with an HTTP 401 or 403 response to trigger the Dynamic Consent flow. Examples include API servers, data stores, tool-hosting services, and inter-service endpoints.

Authorization Code:
: A temporary, single-use credential issued by the Authorization Server to the Client's redirect URI after the Granting User has authenticated and granted consent for a specific Delegated Actor to act on their behalf. The Authorization Code is bound to the Granting User, Client, and the consented Delegated Actor.

Actor Token:
: A security token (e.g., a JWT {{RFC7519}}) used by a Delegated Actor to cryptographically authenticate itself to the Authorization Server during the token exchange. The `sub` claim of an Actor Token MUST identify the Delegated Actor. A Delegated Actor obtains an Actor Token through a separate authentication mechanism (e.g., client credentials grant, mutual TLS, or an identity provider flow); see {{actor-token-acquisition}} for detailed recommendations.

Access Token:
: An access token issued by the Authorization Server, permitting the bearer to access protected resources on behalf of a specific Granting User. When issued via this flow, the Access Token explicitly documents the delegation path through structured claims identifying the Granting User, the Delegated Actor, and the Client.

Pushed Authorization Request (PAR):
: A mechanism defined in {{RFC9126}} that allows the Client to submit authorization request parameters directly to the Authorization Server via a back-channel POST request, receiving a `request_uri` in return. The Client then uses this `request_uri` in the front-channel redirect. PAR is the authorization initiation mechanism used by this specification, providing request integrity protection and enabling upfront validation of the Delegated Actor before the Granting User is redirected for authorization.

Step-Up Authorization Challenge:
: A mechanism by which a Resource Server signals to a Client that the authorization associated with the presented access token does not meet the Resource Server's requirements (e.g., HTTP 401 Unauthorized due to an invalid/missing token, or HTTP 403 Forbidden due to insufficient scope). In this specification, the Step-Up Authorization Challenge is the RECOMMENDED mechanism for Resource Servers to trigger the Dynamic Consent flow.

# 3. Protocol Overview

This section provides a high-level summary of the delegation flow using Pushed Authorization Requests (PAR) {{RFC9126}}. Detailed normative requirements for each step are specified in Sections 4 through 8. For applicability to CIBA and the standard Authorization Code Grant (direct mode), see {{ciba-appendix}} and {{direct-appendix}} respectively.

## 3.1. High-Level Flow

1. The Delegated Actor signals to the Client that it needs to perform an action on the Granting User's behalf, or use the Client as a means to obtain access to act upon the Granting User's resources, providing its identifier (ActorID) and optionally describing the desired action.

2. The Client attempts the action by making a request to the Resource Server (with an existing access token, if available).

3. If access is unsuccessful (e.g., HTTP 401 or HTTP 403), the Resource Server challenges the Client. This challenge triggers the Dynamic Consent mechanism.

4. The Client submits the authorization parameters to the Authorization Server's PAR endpoint, including the `requested_actor` and the required scopes. The Client SHOULD include the `actor_token` for upfront validation.

5. The Authorization Server validates the request parameters, including recording the `requested_actor` and (if provided) validating the `actor_token`. The `requested_actor` is bound to the authorization session.

6. The Authorization Server returns a `request_uri`. The Client redirects the Granting User's user-agent to the Authorization Server using the `request_uri`.

7. The Authorization Server authenticates the Granting User and presents a consent screen detailing the Client, the Delegated Actor, and the requested permissions. This is the "human-in-the-loop" decision point.

8. Upon Granting User consent, the Authorization Server issues an Authorization Code and redirects the user-agent to the Client's `redirect_uri`.

9. The Client exchanges the Authorization Code at the token endpoint, including the `actor_token` and PKCE `code_verifier`.

10. The Authorization Server validates the request and issues an Access Token (JWT per {{RFC9068}}) containing claims that identify the Granting User (`sub`), the Client (`azp`), and the Delegated Actor (`act`).

11. The Client retries the action on the Resource Server using the newly obtained Access Token.

12. The Resource Server validates the Access Token (including the delegation claims) and processes the request.

## 3.2. Sequence Diagram

The following diagram illustrates the delegation flow using PAR.

~~~ ascii-art
    +-----------+   +--------+   +-----------------+   +---------------------+   +---------------+
    | User-Agent|   | Client |   | Delegated Actor |   | Authorization Server|   | Resource Server|
    +-----------+   +--------+   +-----------------+   +---------------------+   +---------------+
          |             |              |                   |                       |
          |     (1) Signals need to act on Granting User's behalf                 |
          |             |  by passing ActorID and requested scopes                 |
          |             |<-------------|                   |                       |
          |             |              |                   |                       |
          |             |              (2) Client attempts action                  |
          |             |-------------------------------------------------------> |
          |             |              |                   |                       |
    /--------------------------------- Access Unsuccessful ---------------------------------\
    |     |             |              |                   |                       |        |
    |------------------------------------[If Unauthorized]----------------------------------|
    |     |             |              |                   |                       |        |
    |     |             |              |             +---------------------------------+   |
    |     |             |              |             | Token validation failed         |   |
    |     |             |              |             +---------------------------------+   |
    |     |             |              |                   |                       |        |
    |     |             |  (3) CHALLENGE: HTTP 401, WWW-Authenticate:              |        |
    |     |             |           Bearer error="invalid_token"                   |        |
    |     |             |<-------------------------------------------------------- |        |
    |     |             |              |                   |                       |        |
    |     |             |  (4) PAR Request to AS           |                       |        |
    |     |             |--------------------------------->|                       |        |
    |     |             |              |                   |                       |        |
    |     |             |  (5) request_uri returned        |                       |        |
    |     |             |<---------------------------------|                       |        |
    |     |             |              |                   |                       |        |
    |  (6) Redirect to AS with request_uri                 |                       |        |
    |     |<------------|              |                   |                       |        |
    |     |             |              |                   |                       |        |
    |     |         (7) Authorization Request              |                       |        |
    |     |----------------------------------------------->|                       |        |
    |     |             |              |                   |                       |        |
    |     |     (8) User Authenticates & Consents          |                       |        |
    |     |<---------------------------------------------->|                       |        |
    |     |             |              |                   |                       |        |
    |------------------------------------[If Forbidden]------------------------------------|
    |     |             |              |                   |                       |        |
    |     |             |              |            +---------------------------------+    |
    |     |             |              |            |   Insufficient Authorization   |    |
    |     |             |              |            +---------------------------------+    |
    |     |             |              |                   |                       |        |
    |     |               (9) CHALLENGE: HTTP 403, WWW-Authenticate:               |        |
    |     |       Bearer error="insufficient_scope" required_scope="scope1 scope2" |        |
    |     |             |<-------------------------------------------------------- |        |
    |     |             |              |                   |                       |        |
    |     |             |  (10) PAR Request to AS with required scopes             |        |
    |     |             |--------------------------------->|                       |        |
    |     |             |              |                   |                       |        |
    |     |             |  (11) request_uri returned       |                       |        |
    |     |             |<---------------------------------|                       |        |
    |     |             |              |                   |                       |        |
    |  (12) Redirect to AS with request_uri                |                       |        |
    |     |<------------|              |                   |                       |        |
    |     |             |              |                   |                       |        |
    |     |         (13) Authorization Request             |                       |        |
    |     |----------------------------------------------->|                       |        |
    |     |             |              |                   |                       |        |
    |     |            (14) User Consents                  |                       |        |
    |     |<---------------------------------------------->|                       |        |
    |---------------------------------------------------------------------------------------|
    |     |             |              |                   |                       |        |
    |     | (15) Redirect with Authorization Code          |                       |        |
    |     |<-----------------------------------------------|                       |        |
    |     |             |              |                   |                       |        |
    |     | (16) Authorization Code    |                   |                       |        |
    |     |------------>|              |                   |                       |        |
    |     |             |              |                   |                       |        |
    |     |             | (17) Token Request with actor_token                      |        |
    |     |             |--------------------------------->|                       |        |
    |     |             |              |                   |                       |        |
    |     |             |  (18) Access Token (JWT)         |                       |        |
    |     |             |<---------------------------------|                       |        |
    |     |             |              |                   |                       |        |
    |     |             |  (19) Client Retries Action with Access Token            |        |
    |     |             |--------------------------------------------------------->|        |
    \---------------------------------------------------------------------------------------/
    /------------------------------------ Access Successful --------------------------------\
    |     |             |              |                   |                       |        |
    |     |             |  (20) Protected Resource / Action Succeeded              |        |
    |     |             |<---------------------------------------------------------|        |
    \---------------------------------------------------------------------------------------/
~~~

# 4. Authorization Request

This section defines the authorization request flow using Pushed Authorization Requests (PAR) {{RFC9126}}. The Client submits authorization parameters directly to the Authorization Server's PAR endpoint over a back-channel connection, receiving a `request_uri` that is subsequently used to redirect the Granting User for consent.

> **Note:** For deployments where the Authorization Server does not support PAR, the same delegation parameters can be used with a direct front-channel Authorization Code Grant request. See {{direct-appendix}} for the full specification. For ambient use cases where the Granting User is not actively interacting with the Client, see {{ciba-appendix}} for the CIBA-based flow.

## 4.1. Actor Validation Model

In both the PAR-based flow and the Direct Authorization Code Grant mode ({{direct-appendix}}), the authorization request MAY be initiated with only the `requested_actor` parameter, without an `actor_token`. The `actor_token` is REQUIRED at the token endpoint, where the Authorization Server performs authoritative Delegated Actor authentication and MUST verify that the `actor_token`'s `sub` claim matches the `requested_actor` bound to the Authorization Code.

This design allows the authorization and consent flow to proceed based solely on the `requested_actor` identifier, deferring cryptographic actor authentication to the token exchange. The Granting User consents to delegation to a named Delegated Actor, and the `actor_token` presented at the token endpoint proves that the entity requesting the token is in fact that actor.

## 4.2. Upfront Actor Validation (PAR)

When using PAR, the Client SHOULD include the `actor_token` and `actor_token_type` parameters in the PAR request for upfront validation. If provided, the Authorization Server MUST validate the `actor_token` before prompting the Granting User for consent. This upfront validation provides additional security benefits:

* Confirms the Delegated Actor's identity and token validity before the Granting User is asked to make a consent decision.
* Prevents wasted user interactions if the Delegated Actor's credentials are invalid, expired, or revoked.
* Binds the validated actor identity to the `request_uri` session, enabling the Authorization Server to verify continuity at the token endpoint.

If the `actor_token` is included and fails upfront validation, the Authorization Server MUST reject the request with the error code `invalid_actor_token` and MUST NOT continue to the authorization flow, leaving the Granting User uninvolved.

> **Note:** Upfront actor validation is not available in the Direct Authorization Code Grant mode ({{direct-appendix}}), because the `actor_token` MUST NOT be transmitted through the user-agent. In direct mode, the `actor_token` is only presented at the token endpoint.

## 4.3. PAR Request

~~~
POST /par HTTP/1.1
Host: authorization-server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client_credentials>

response_type=code&
client_id=<client_id>&
redirect_uri=<redirect_uri>&
scope=<scope>&
code_challenge=<code_challenge>&
code_challenge_method=S256&
requested_actor=<actor_id>&
actor_token=<actor_token>&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

## 4.4. Request Parameters

The following parameters are defined for the authorization request.

response_type:
: REQUIRED. Value MUST be set to `code`, per OAuth 2.0 (Section 4.1.1 of {{RFC6749}}).

client_id:
: REQUIRED. The identifier of the Client as registered with the Authorization Server.

redirect_uri:
: REQUIRED. The Client's redirection endpoint as registered with the Authorization Server.

scope:
: RECOMMENDED. A space-delimited list of OAuth 2.0 scope values representing the permissions the Delegated Actor requires (e.g., `read:email write:calendar`). Deployments MAY use prefixed scope values to convey the Delegated Actor's intent (see {{consent-scope-prefix}}).

state:
: RECOMMENDED. An opaque value used by the Client to maintain state between the request and callback, per Section 4.1.1 of {{RFC6749}}.

code_challenge:
: REQUIRED. The PKCE code challenge, per {{RFC7636}}.

code_challenge_method:
: REQUIRED. Value MUST be set to `S256`, per {{RFC7636}}.

requested_actor:
: REQUIRED. The unique identifier of the Delegated Actor for which the Client is requesting delegated access on behalf of the Granting User. This identifier MUST uniquely identify the Delegated Actor within the Authorization Server's domain and MUST be understood by the Authorization Server.

actor_token:
: RECOMMENDED for PAR. The security token used to authenticate the Delegated Actor, submitted for upfront validation. This token MUST be a valid token (e.g., a JWT {{RFC7519}}) issued to the Delegated Actor and MUST include the `sub` claim identifying the Delegated Actor. If provided, the Authorization Server MUST validate this token and bind the verified actor identity to the resulting `request_uri`. If not provided, the flow proceeds with the `requested_actor` identifier alone; the `actor_token` is then REQUIRED at the token endpoint (see Section 6). In the Direct Authorization Code Grant mode ({{direct-appendix}}), this parameter MUST NOT be included in the front-channel request; it is only presented at the token endpoint. In the CIBA mode ({{ciba-appendix}}), the `actor_token` MUST be included in the back-channel initiation request.

actor_token_type:
: REQUIRED if `actor_token` is present. An identifier for the type of the `actor_token`, per Section 3 of {{RFC8693}}. For JWT-based actor tokens, the value MUST be `urn:ietf:params:oauth:token-type:jwt`.

## 4.5. Authorization Server Processing

Upon receiving the PAR request, the Authorization Server MUST perform the following steps:

1. Authenticate the Client if applicable.

2. Validate the request parameters according to {{RFC9126}} and the parameter definitions above.

3. Record the `requested_actor` value and bind it to the `request_uri` session. The Authorization Server MAY optionally validate the `requested_actor` against a registry of known Delegated Actor identities if one is maintained, and MAY reject the request with the error code `invalid_actor` if the actor has been explicitly blocked by policy. However, pre-registration of actor identities is NOT REQUIRED; the Authorization Server MAY accept any `requested_actor` value, deferring authoritative actor authentication to the token endpoint where the `actor_token` is mandatory.

4. If `actor_token` is present (upfront validation):
   a. Validate the token's signature, issuer, audience (if applicable), and expiration. The token MUST NOT be expired or revoked. If the issuer is external, the Authorization Server SHOULD verify trust in the issuer over a preferred mechanism.
   b. Extract the Delegated Actor identity from the `actor_token`'s `sub` claim.
   c. Verify that the `sub` claim matches the `requested_actor` parameter. If they do not match, the Authorization Server MUST return an error with the error code `actor_mismatch`.
   d. Bind the validated actor identity to the `request_uri` session alongside the `requested_actor`.

5. If `actor_token` is NOT present, the flow proceeds with the `requested_actor` identifier alone. The Authorization Server binds the `requested_actor` to the authorization session; authoritative Delegated Actor authentication will occur at the token endpoint.

6. If all validations pass, return the `request_uri`.

## 4.6. PAR Response

If the request is valid, the Authorization Server returns a `request_uri`:

~~~
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
  "expires_in": 60
}
~~~

If validation fails, the Authorization Server returns an error response per {{RFC9126}} Section 2.3, using the error codes defined in Section 9.

## 4.7. Front-Channel Redirect and Consent

The Client then redirects the Granting User's user-agent using the `request_uri`:

~~~
GET /authorize?client_id=<client_id>&request_uri=urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c HTTP/1.1
Host: authorization-server.example.com
~~~

The Authorization Server resolves the `request_uri` and presents a consent screen to the Granting User (the "human-in-the-loop" decision point). This screen SHOULD clearly indicate:

* The name or identity of the Client application initiating the request.
* The identity and description of the Delegated Actor (`requested_actor`) for which delegation is being requested.
* The specific scopes of access being requested.
* A clear indication that the Granting User is authorizing an autonomous entity to act on their behalf.

Upon consent, the Authorization Server issues an Authorization Code as defined in Section 5. If the Granting User denies consent, the Authorization Server MUST return an error response with the error code `authorization_denied`.

# 5. Authorization Response

## 5.1. Authorization Code Response

If the Granting User grants consent, the Authorization Server issues an Authorization Code and redirects the user-agent back to the Client's `redirect_uri`.

~~~
HTTP/1.1 302 Found
Location: <redirect_uri>?code=<authorization_code>&state=<state>
~~~

### 5.1.1. Parameters

code:
: REQUIRED. The Authorization Code issued by the Authorization Server. This code is bound to the tuple (Granting User, Client, `requested_actor`, granted scopes). If the authorization was initiated via PAR with an upfront-validated `actor_token`, the validated actor identity is also bound to this code. In all cases, the `requested_actor` is bound to the code and will be verified against the `actor_token` at the token endpoint.

state:
: REQUIRED if the `state` parameter was present in the authorization request. The exact value received from the Client.

## 5.2. Authorization Endpoint Error Response

If the request fails or the Granting User denies consent, the Authorization Server redirects the user-agent back to the Client's `redirect_uri` with error parameters.

~~~
HTTP/1.1 302 Found
Location: <redirect_uri>?error=<error_code>&error_description=<description>&state=<state>
~~~

See Section 9 for the complete list of error codes applicable to the authorization and PAR endpoints.

# 6. Access Token Request and Response

## 6.1. Token Request

The Client exchanges the Authorization Code for an Access Token at the Authorization Server's token endpoint using the `authorization_code` grant type. The Client MUST include the `actor_token` parameter to authenticate the Delegated Actor at the point of token issuance.

~~~
POST /token HTTP/1.1
Host: authorization-server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client_credentials>

grant_type=authorization_code&
client_id=<client_id>&
code=<authorization_code>&
code_verifier=<code_verifier>&
redirect_uri=<redirect_uri>&
actor_token=<actor_token>&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

### 6.1.1. Request Parameters

grant_type:
: REQUIRED. Value MUST be set to `authorization_code`.

client_id:
: REQUIRED. The identifier of the Client, per Section 4.1.3 of {{RFC6749}}. Confidential clients MUST also authenticate using their registered authentication method (e.g., `client_secret_basic`, `client_secret_post`, or `private_key_jwt`). Public clients MUST include the `client_id` but do not authenticate.

code:
: REQUIRED. The Authorization Code received from the Authorization Server.

code_verifier:
: REQUIRED. The PKCE code verifier corresponding to the `code_challenge` sent in the authorization request, per {{RFC7636}}.

redirect_uri:
: REQUIRED. The same `redirect_uri` value that was included in the authorization request.

actor_token:
: REQUIRED. The security token used to authenticate the Delegated Actor at the moment of token issuance. This token MUST be a valid token (e.g., a JWT {{RFC7519}}) issued to the Delegated Actor and MUST include the `sub` claim identifying the Delegated Actor. The `sub` claim MUST match the `requested_actor` value that was bound to the Authorization Code during the authorization request. The Client MUST send the `actor_token` regardless of whether it was previously submitted during PAR initiation; this is the authoritative point at which the Delegated Actor's identity is cryptographically verified.

actor_token_type:
: REQUIRED. An identifier for the type of the `actor_token`, per Section 3 of {{RFC8693}}. For JWT-based actor tokens, the value MUST be `urn:ietf:params:oauth:token-type:jwt`.

## 6.2. Authorization Server Validation (Token Endpoint)

Upon receiving the token request, the Authorization Server MUST perform the following steps:

1. Validate the request parameters according to the OAuth 2.0 Token Endpoint (Section 4.1.3 of {{RFC6749}}), including client authentication.

2. Validate the `actor_token`: the Authorization Server MUST verify the token's signature, issuer, audience (if applicable), and expiration. The token MUST NOT be expired or revoked. If the issuer is external, the Authorization Server MUST verify trust in the issuer over a preferred mechanism.

3. Extract the Delegated Actor identity from the `actor_token`'s `sub` claim.

4. Verify that the `sub` claim of the `actor_token` matches the `requested_actor` value that was bound to the Authorization Code during the authorization request. If they do not match, the Authorization Server MUST reject the request with the error code `actor_mismatch`. This step is the authoritative binding between the Delegated Actor's cryptographic identity and the `requested_actor` that the Granting User consented to.

5. **Actor Continuity Check (PAR with upfront validation only):** If the authorization was initiated via PAR and an `actor_token` was validated and bound during the PAR request, the Authorization Server MUST additionally verify that the `actor_token` presented at the token endpoint identifies the same Delegated Actor that was bound to the PAR session (`request_uri`). This ensures continuity between the upfront validation and the token issuance. (Note: This check applies only when an `actor_token` was provided during PAR initiation. When PAR was initiated without an `actor_token`, or when using the Direct Authorization Code Grant mode ({{direct-appendix}}), step 4 is the sole actor identity verification.)

6. Validate the PKCE `code_verifier` against the `code_challenge` associated with the Authorization Code.

If all validations pass, the Authorization Server issues an Access Token. If any validation fails, the Authorization Server MUST return an appropriate error response.

## 6.3. Access Token Response

If the token request is valid, the Authorization Server issues an Access Token. This token SHOULD be a JSON Web Token (JWT) {{RFC7519}} conforming to {{RFC9068}}, to include claims that document the delegation chain.

~~~
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "<delegated_access_token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "<granted_scope>"
}
~~~

### 6.3.1. Response Parameters

access_token:
: REQUIRED. The access token issued by the Authorization Server.

token_type:
: REQUIRED. The type of the token issued, typically `Bearer`.

expires_in:
: RECOMMENDED. The lifetime in seconds of the access token.

scope:
: OPTIONAL if identical to the scope requested; otherwise REQUIRED. The scopes granted by the Authorization Server.

## 6.4. Token Endpoint Error Response

If the request is invalid, the Authorization Server returns an error response with an HTTP 400 (Bad Request) status code.

~~~
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "error": "<error_code>",
  "error_description": "<human_readable_description>"
}
~~~

See Section 9 for the complete list of error codes applicable to the token endpoint.

# 7. Access Token Structure and Claims

The Access Token SHOULD be a JWT Profile for OAuth 2.0 Access Tokens {{RFC9068}}. It MUST carry claims that explicitly document the delegation chain from the Granting User, through the Client, to the Delegated Actor.

In addition to standard JWT claims (e.g., `iss`, `aud`, `exp`, `iat`, `jti`), an Access Token issued via this flow MUST contain the following claims:

sub:
: REQUIRED. The unique identifier of the Granting User (the resource owner who consented to the delegation).

azp:
: REQUIRED. The `client_id` of the Client application that facilitated the delegation flow.

scope:
: REQUIRED. The granted scope values, representing the permissions the Delegated Actor is authorized to exercise.

act:
: REQUIRED. The actor claim, representing the Delegated Actor that is acting on behalf of the Granting User (Section 4.1 of {{RFC8693}}). This claim MUST contain a JSON object with at least the following member:
  * sub: REQUIRED. The unique identifier of the Delegated Actor.
  * Additional members (e.g., a human-readable name or type) MAY be included in the `act` claim.

Example Decoded JWT Payload:

~~~json
{
  "iss": "https://authorization-server.example.com/oauth2/token",
  "aud": "https://resource-server.example.com",
  "sub": "user-456",
  "azp": "s6BhdRkqt3",
  "scope": "read:email write:calendar",
  "exp": 1746009896,
  "iat": 1746006296,
  "jti": "unique-token-id-7f3a",
  "act": {
    "sub": "secondary-actor-assistant-v2"
  }
}
~~~

Resource Servers consuming this token can inspect the `sub` claim to identify the Granting User and the `act.sub` claim to identify the specific Delegated Actor that is performing the action. This provides a clear, auditable delegation path and enables Resource Servers to apply actor-specific access policies.

# 8. Resource Server Behavior and Dynamic Consent

The authorization flow defined in this specification is typically triggered by a Resource Server challenge, such as an HTTP 401 (Unauthorized) or 403 (Forbidden) response, indicating a missing, invalid, or insufficient access token. This challenge is the primary trigger for the Dynamic Consent mechanism.

## 8.1. Resource Server Request

When the Client, prompted by a Delegated Actor, requests a protected resource, it includes an access token in the Authorization header if available.

~~~
GET /some/protected/resource HTTP/1.1
Host: resource-server.example.com
Authorization: Bearer <existing_access_token_if_any>
~~~

## 8.2. Resource Server Token Validation

Upon receiving the request, the Resource Server MUST validate the Access Token (if provided). This validation includes:

1. Ensuring the token is present if required for the resource.

2. Verifying the token's signature, issuer (`iss`), and audience (`aud`).

3. Checking if the token is expired or revoked.

4. Confirming the token contains the necessary scopes for the requested action.

5. If the resource requires action on behalf of a specific Delegated Actor, verifying the token contains the appropriate delegation claims (e.g., an `act` claim) and that the `act.sub` value identifies an authorized Delegated Actor.

If the Access Token is missing, invalid, or insufficient for the requested action, the Resource Server MUST return an error response, typically an HTTP 401 (Unauthorized) or HTTP 403 (Forbidden), including a `WWW-Authenticate` header.

## 8.3. WWW-Authenticate Challenge

The Resource Server MUST include a `WWW-Authenticate` header field in the response to indicate the reason for the challenge. This header field MUST include the error code and other relevant information to enable the Client to determine the appropriate remediation action.

Example (insufficient scope):

~~~
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
  error_description="The access token does not have the required scope(s)",
  required_scope="scope1 scope2"
Content-Type: application/json;charset=UTF-8

{
  "error": "insufficient_scope",
  "error_description": "The access token does not have the required scope(s)",
  "required_scope": "scope1 scope2"
}
~~~

Example (missing or invalid delegation):

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  error_description="Access token missing required delegation claims"
Content-Type: application/json;charset=UTF-8

{
  "error": "invalid_token",
  "error_description": "Access token missing required delegation claims (act)"
}
~~~

Upon receiving such a challenge, the Client SHOULD initiate the Dynamic Consent flow by submitting a PAR request to the Authorization Server.

## 8.4. Dynamic Consent Hand-Off

The "human-in-the-loop" hand-off process works as follows:

1. **Interruption:** The Delegated Actor requests the Client to perform an action at the Resource Server. The Resource Server responds with a challenge (401 or 403).

2. **PAR Submission:** The Client submits the authorization parameters (including `requested_actor`, `actor_token`, and the required scopes) to the Authorization Server's PAR endpoint to obtain a `request_uri`.

3. **User Redirect:** The Client redirects the Granting User's user-agent to the Authorization Server using the `request_uri`.

4. **Consent Decision:** The Authorization Server presents the consent screen. The Granting User reviews the requested delegation and either grants or denies consent.

5. **Flow Resumption:** Upon granting consent, the Authorization Server redirects the user-agent back to the Client with an Authorization Code. The Client completes the token exchange (including `actor_token` validation) and retries the action at the Resource Server. The Delegated Actor's operation resumes transparently.

6. **Denial Handling:** If the Granting User denies consent, the Authorization Server redirects back with `error=authorization_denied`. The Client MUST communicate the denial to the Delegated Actor so it can gracefully handle the refusal (e.g., abandon the action or attempt a fallback).

# 9. Error Codes

This section consolidates all error codes defined by this specification. Standard OAuth 2.0 error codes ({{RFC6749}}) also apply where indicated. For additional error codes specific to CIBA, see {{ciba-appendix}}.

## 9.1. Initiation and Authorization Endpoint Errors

The following error codes are defined for the authorization and PAR endpoints in addition to those in Section 4.1.2.1 of {{RFC6749}}:

authorization_denied:
: The Granting User explicitly denied consent for the Delegated Actor delegation.

invalid_actor:
: The `requested_actor` parameter contains an identifier that the Authorization Server has explicitly blocked by policy, or one that fails a registry check (if the Authorization Server maintains a registry of known Delegated Actor identities).

invalid_actor_token:
: The `actor_token` provided for upfront validation is invalid, expired, revoked, or its signature cannot be verified.

actor_mismatch:
: The identity in the `actor_token` (its `sub` claim) does not match the `requested_actor` parameter.

## 9.2. Token Endpoint Errors

The following error codes are defined for the token endpoint in addition to those in Section 5.2 of {{RFC6749}}:

actor_mismatch:
: The identity in the `actor_token` (its `sub` claim) does not match the `requested_actor` value bound to the Authorization Code.

invalid_actor_token:
: The `actor_token` is invalid, expired, revoked, or its signature cannot be verified.

# 10. Security Considerations

## 10.1. Delegated Actor Authentication

The security of this flow relies heavily on the Authorization Server's ability to securely authenticate the Delegated Actor during the token request using the Actor Token. The method by which Delegated Actors obtain and secure their Actor Tokens is critical and outside the scope of the normative sections of this specification, but MUST be implemented securely. See {{actor-token-acquisition}} for detailed recommendations on actor identity models, token acquisition mechanisms, and issuer trust establishment. Authorization Servers SHOULD require strong authentication methods for Delegated Actors, such as asymmetric key-based JWT assertion (e.g., `private_key_jwt`) or mutual TLS rather than shared secrets.

## 10.2. PAR Security Benefits

PAR {{RFC9126}} provides the following security benefits for delegation flows, which is why this specification defines the authorization flow using PAR. The authorization parameters (including `requested_actor`, `actor_token`, and `scope`) are transmitted server-to-server over TLS, rather than through the Granting User's user-agent. This provides:

* **Request Integrity:** Authorization parameters cannot be tampered with by malicious browser extensions, compromised user-agents, or man-in-the-browser attacks.
* **Upfront Actor Validation:** The Authorization Server validates the `actor_token` before the Granting User is prompted, ensuring invalid or expired actors are rejected early.
* **Reduced Attack Surface:** The `actor_token` is never exposed in the user-agent's URL bar, history, or referrer headers.

The Direct Authorization Code Grant mode ({{direct-appendix}}) does not provide these benefits; it is retained only as a baseline for deployments where PAR is not available.

## 10.3. Actor Token Continuity

When the `actor_token` is submitted for upfront validation during the PAR request, the Authorization Server binds the validated actor identity to the authorization session. The `actor_token` is REQUIRED at the token endpoint for all flows (PAR, Direct, and CIBA). The Authorization Server MUST verify that the `actor_token`'s `sub` claim matches the `requested_actor` value bound to the Authorization Code. This is the authoritative point at which the Delegated Actor's identity is cryptographically verified and bound to the delegation.


This two-phase validation ensures that the Delegated Actor remains authorized between the time the Granting User consents and the time the token is actually issued, mitigating time-of-check-to-time-of-use (TOCTOU) attacks.

### 10.3.1. Flows Without Upfront Validation

When the authorization request was initiated without an `actor_token` (either in PAR mode without upfront validation, or in Direct mode), the token endpoint validation is the sole point of Delegated Actor authentication. The Authorization Server MUST verify the `actor_token`'s validity and confirm that its `sub` claim matches the `requested_actor` value that the Granting User consented to. This ensures that only the intended Delegated Actor can obtain the delegated access token.

## 10.4. Proof Key for Code Exchange (PKCE)

PKCE {{RFC7636}} is REQUIRED for all authorization requests in this flow, to prevent authorization code interception attacks. This is especially important given that the authorization code ultimately results in a delegated token with an `act` claim, magnifying the impact of any code interception. The `code_challenge_method` MUST be `S256`.

## 10.5. Single-Use and Short-Lived Authorization Codes

Authorization Codes MUST be single-use and have a short expiration time (RECOMMENDED no more than 10 minutes) to minimize the window for compromise. The Authorization Server MUST reject any attempt to reuse an Authorization Code and SHOULD revoke all tokens issued based on that code if reuse is detected.

## 10.6. Binding Code to Delegated Actor and Client

The Authorization Server MUST bind the Authorization Code to the specific Granting User, Client (`client_id`), and Delegated Actor (`requested_actor`) during issuance and MUST verify this binding during the token request. If the `actor_token`'s `sub` claim does not match the `requested_actor` bound to the code, the token request MUST be rejected with the `actor_mismatch` error.

## 10.7. Clear and Informed User Consent

The consent screen presented to the Granting User MUST clearly identify the Delegated Actor and the requested scopes to ensure the Granting User understands exactly what authority they are delegating and to whom. The consent screen SHOULD explicitly indicate that an autonomous entity will be exercising the delegated permissions.

## 10.8. Privilege Escalation Prevention

Because Delegated Actors are autonomous and potentially dynamic, preventing privilege escalation is critical:

Scope Confinement:
: The Authorization Server MUST NOT issue an Access Token with scopes exceeding those explicitly consented to by the Granting User. The `act` claim in the Access Token signals to Resource Servers that the bearer is acting through delegation, and Resource Servers SHOULD apply additional scrutiny or restrictive policies to requests bearing an `act` claim.

Token Confinement:
: Access Tokens issued via this flow SHOULD have a short lifetime (RECOMMENDED no more than one hour) and SHOULD NOT be issued with refresh tokens unless the Authorization Server has established a high level of trust with the Delegated Actor. If refresh tokens are issued, they MUST be bound to the specific Delegated Actor and MUST be rotated on each use.

Compromised Actor Logic:
: If a Delegated Actor's logic is compromised (e.g., prompt injection in an AI agent, or code injection in an automated script), the attacker could attempt to use the delegated token for unintended purposes. To mitigate this risk:

  * Resource Servers SHOULD enforce fine-grained authorization policies based on the `act` claim, limiting the actions a specific Delegated Actor type can perform regardless of the scopes in the token.
  * Authorization Servers SHOULD support token revocation endpoints and provide mechanisms for Granting Users to revoke all active delegations to a specific Delegated Actor.
  * Clients SHOULD implement anomaly detection and rate limiting on actions requested by Delegated Actors.

Actor Impersonation:
: The Authorization Server MUST ensure that the `actor_token` presented at the token endpoint was issued to the same entity identified by `requested_actor`. This binding prevents a malicious Delegated Actor from presenting its own `actor_token` while using a code intended for a different (more privileged) Delegated Actor.

## 10.9. Dynamic Consent Replay Prevention

Because the Dynamic Consent flow can be triggered repeatedly (e.g., by a compromised Resource Server sending spurious 401/403 challenges), the following mitigations apply:

* The Authorization Server SHOULD implement consent caching: if the Granting User has recently consented to the same (Client, Delegated Actor, scope) tuple, the Authorization Server MAY skip the interactive consent screen and issue a new code without re-prompting, subject to a configurable consent validity period.
* Clients MUST validate that the resource server challenge is legitimate before initiating the Dynamic Consent flow. Clients SHOULD NOT blindly redirect the Granting User to the Authorization Server on every 401/403 response.

## 10.10. Auditability

The structured claims in the Access Token (`sub`, `azp`, `act`) provide essential information for auditing actions performed using the token, clearly showing who (Granting User) authorized the action, which application (Client) facilitated it, and which entity (Delegated Actor) performed it. Authorization Servers and Resource Servers SHOULD log delegation events for forensic and compliance purposes.

## 10.11. Token Storage and Transmission

Access Tokens and Actor Tokens MUST be transmitted only over TLS-protected channels. Clients and Delegated Actors MUST store tokens securely and MUST NOT expose them in URLs, logs, or error messages.

# 11. IANA Considerations

## 11.1. OAuth Parameters Registration

This specification registers the following parameters in the "OAuth Parameters" registry established by {{RFC6749}}:

* `requested_actor` -- Used at the authorization and PAR endpoints to identify the Delegated Actor.

## 11.2. OAuth Extensions Error Registration

This specification registers the following error codes in the "OAuth Extensions Error Registry":

* `authorization_denied` -- Indicates that the Granting User denied consent for the delegation request.
* `invalid_actor` -- Indicates that the `requested_actor` is invalid or blocked by policy.
* `invalid_actor_token` -- Indicates that the `actor_token` is invalid, expired, revoked, or cannot be verified.
* `actor_mismatch` -- Indicates that the `actor_token`'s `sub` claim does not match the `requested_actor` value.
* `invalid_binding_message` -- (CIBA-specific) Indicates that the `binding_message` provided in a CIBA initiation request is invalid or does not meet policy requirements.

# 12. Use Case Example: AI-Driven Personal Assistant (PAR Flow)

**Scenario:** A user ("Alice") uses a productivity application ("WorkHub") that integrates with an AI personal assistant ("AssistBot"). Alice asks AssistBot to schedule a meeting with a colleague by checking her calendar and sending an invitation on her behalf.

## 12.1. Step 1: Delegated Actor Signals Intent

AssistBot (the Delegated Actor, identifier: `assistbot-v2`) signals to WorkHub (the Client) that it needs to read Alice's calendar and create an event.

## 12.2. Step 2: Client Attempts Action

WorkHub makes a request to Alice's calendar service (the Resource Server):

~~~
GET /api/calendar/events HTTP/1.1
Host: calendar.example.com
Authorization: Bearer <existing_token_without_act_claim>
~~~

## 12.3. Step 3: Resource Server Challenge

The calendar service determines the token lacks the required delegation claims and responds:

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  error_description="Access token missing required delegation claims"
~~~

## 12.4. Step 4: Dynamic Consent via PAR (Human-in-the-Loop)

WorkHub submits the authorization parameters to the Authorization Server's PAR endpoint, including AssistBot's Actor Token for upfront validation:

~~~
POST /par HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code&
client_id=workhub-app&
redirect_uri=https://workhub.example.com/callback&
scope=read:calendar write:calendar intent:schedule_meeting_with_colleague&
state=xy9z3k&
code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
code_challenge_method=S256&
requested_actor=assistbot-v2&
actor_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

The Authorization Server validates the `actor_token` upfront, confirms that `assistbot-v2` is a recognized Delegated Actor, and returns a `request_uri`:

~~~
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{
  "request_uri": "urn:ietf:params:oauth:request_uri:workhub_cal_7f3a",
  "expires_in": 60
}
~~~

WorkHub then redirects Alice's browser using the `request_uri`:

~~~
GET /authorize?client_id=workhub-app&request_uri=urn:ietf:params:oauth:request_uri:workhub_cal_7f3a HTTP/1.1
Host: auth.example.com
~~~

## 12.5. Step 5: Granting User Consent

The Authorization Server displays a consent screen to Alice:

> **WorkHub** is requesting that **AssistBot (v2)** be allowed to act on your behalf:
>
> - **Read** your calendar events
> - **Create** calendar events
>
> **Purpose:** Schedule a meeting with a colleague
>
> [Allow]  [Deny]

Alice clicks "Allow."

## 12.6. Step 6: Authorization Code Issued

~~~
HTTP/1.1 302 Found
Location: https://workhub.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xy9z3k
~~~

## 12.7. Step 7: Token Exchange with Actor Authentication

WorkHub exchanges the code at the token endpoint, including AssistBot's Actor Token. The Authorization Server verifies that this `actor_token` identifies the same Delegated Actor (`assistbot-v2`) that was validated during the PAR request (actor continuity check):

~~~
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
client_id=workhub-app&
code=SplxlOBeZQQYbYS6WxSbIA&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
redirect_uri=https://workhub.example.com/callback&
actor_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

## 12.8. Step 8: Delegated Access Token Issued

~~~json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:calendar write:calendar intent:schedule_meeting_with_colleague"
}
~~~

Decoded JWT payload of the access token:

~~~json
{
  "iss": "https://auth.example.com",
  "aud": "https://calendar.example.com",
  "sub": "alice@example.com",
  "azp": "workhub-app",
  "scope": "read:calendar write:calendar intent:schedule_meeting_with_colleague",
  "exp": 1746009896,
  "iat": 1746006296,
  "jti": "tok-7f3a-1b2c",
  "act": {
    "sub": "assistbot-v2"
  }
}
~~~

## 12.9. Step 9: Action Completed

WorkHub retries the calendar request with the new token. The calendar service validates the `act` claim and processes the request. AssistBot successfully schedules the meeting.

--- back

# Appendix A. Client-Initiated Backchannel Authentication (CIBA) for Ambient Use Cases {#ciba-appendix}

This appendix describes how the delegation parameters and semantics defined in this specification apply to Client-Initiated Backchannel Authentication (CIBA) {{OpenID.CIBA}}. CIBA is appropriate when the Delegated Actor is operating as a background process and the Granting User is NOT currently interacting with the Client (e.g., scheduled batch jobs, background monitoring agents, after-hours automation). The Authorization Server contacts the Granting User through an out-of-band channel (push notification, SMS, authentication app) to obtain consent. See Section 4 of {{OpenID.CIBA}} for the base authentication request specification.

## A.1. CIBA Authentication Request

~~~
POST /bc-authorize HTTP/1.1
Host: authorization-server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client_credentials>

scope=<scope>&
client_id=<client_id>&
login_hint=<granting_user_identifier>&
binding_message=<human_readable_intent_description>&
requested_actor=<actor_id>&
actor_token=<actor_token>&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

## A.2. CIBA-Specific Parameters

In addition to standard OAuth 2.0 parameters (`scope`, `client_id`) and the delegation-specific parameters introduced by this specification (`requested_actor`, `actor_token`, `actor_token_type`), the CIBA request includes parameters defined in Section 7.1 of {{OpenID.CIBA}}. Of particular note:

login_hint:
: REQUIRED. Identifies the Granting User per Section 7.1 of {{OpenID.CIBA}}.

binding_message:
: REQUIRED for this specification. A human-readable string displayed to the Granting User on their authentication device. This message MUST accurately reflect the requested permissions and the Delegated Actor's identity (e.g., `"Allow rebalancer-v1 to execute trades on your portfolio"`).

See Section 7.1 of {{OpenID.CIBA}} for additional standard parameters (`id_token_hint`, `login_hint_token`, `requested_expiry`, `client_notification_token`, etc.).

## A.3. Upfront Actor Validation (CIBA)

The upfront actor validation described in Section 4.1 and Section 4.2 of the main specification applies equally to CIBA. The Client SHOULD include the `actor_token` and `actor_token_type` parameters in the CIBA authentication request. If provided, the Authorization Server MUST validate the `actor_token` before initiating the out-of-band consent flow with the Granting User. The validated actor identity is bound to the resulting `auth_req_id`.

## A.4. Binding Message Integrity

The `binding_message` MUST be semantically consistent with the `scope` parameters or the requested authorization consent. If a mismatch is detected, the Authorization Server MUST reject the request with `invalid_binding_message`. This requirement prevents:

* **Social Engineering via Misleading Messages:** An attacker displaying a benign message (e.g., "Check your account balance") while requesting elevated permissions (e.g., `execute:trades`).
* **Scope/Intent Drift:** A misconfigured Client inadvertently presenting an outdated or incorrect description of the Delegated Actor's intended actions.

The Authorization Server SHOULD implement automated validation when registered scope descriptions are available. The Authorization Server MAY rely on policy-based heuristics or manual review for unrecognized scope values.

## A.5. Authorization Server Processing (CIBA)

Upon receiving the CIBA authentication request, the Authorization Server MUST:

1. Authenticate the Client and validate standard CIBA parameters per Section 7.3 of {{OpenID.CIBA}}.
2. Validate the `requested_actor` and the `actor_token` per the upfront validation rules defined in Section 4.1 and Section 4.5.
3. Validate `binding_message` integrity (see above). If a mismatch is detected, reject with `invalid_binding_message`.
4. Resolve the `login_hint` to identify the Granting User. If the Granting User cannot be identified, reject with `invalid_request`.
5. Initiate the out-of-band consent flow, displaying the `binding_message`, Delegated Actor identity, and requested permissions.

## A.6. CIBA Authentication Response

If valid, the Authorization Server returns an `auth_req_id` per Section 7.3 of {{OpenID.CIBA}}. The `auth_req_id` binds the validated Delegated Actor identity to the pending transaction.

## A.7. CIBA Token Delivery Modes

CIBA defines three token delivery modes -- **poll**, **ping**, and **push** -- as specified in Sections 10, 11, and 12 of {{OpenID.CIBA}} respectively. In all three modes, the `auth_req_id` serves as the secure handle for the pending delegation. Because the Delegated Actor's identity was already validated and bound to the `auth_req_id` during the initial CIBA authentication request, subsequent requests to the token endpoint SHOULD NOT include the `actor_token` unless the Authorization Server requires a fresh proof-of-presence at the moment of token issuance. If fresh proof-of-presence is required, the Authorization Server MUST advertise this via its discovery metadata (e.g., `ciba_actor_token_at_token_endpoint_required: true`).

### A.7.1. Poll Mode

The Client polls the token endpoint per Section 10 of {{OpenID.CIBA}}:

~~~
POST /token HTTP/1.1
Host: authorization-server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client_credentials>

grant_type=urn:openid:params:grant-type:ciba&
auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1&
client_id=<client_id>
~~~

The Authorization Server returns `authorization_pending` while the Granting User has not responded. The Client MUST respect the `interval` value and MUST NOT poll more frequently. Upon consent, the Authorization Server returns an Access Token with the delegation claims defined in Section 7. If consent is denied, the Authorization Server returns `error=authorization_denied`.

### A.7.2. Ping Mode

In ping mode (Section 11 of {{OpenID.CIBA}}), the Authorization Server notifies the Client's pre-registered callback endpoint with the `auth_req_id` when the Granting User responds. The Client then retrieves the token from the token endpoint using the same request format as poll mode. The Client MUST validate the `client_notification_token` on every callback invocation.

### A.7.3. Push Mode

In push mode (Section 12 of {{OpenID.CIBA}}), the Authorization Server delivers the Access Token directly to the Client's callback endpoint upon Granting User consent. No Client-initiated token request occurs. The pushed Access Token MUST contain the same delegation claims (`sub`, `azp`, `act`) as tokens issued through poll or ping modes. Because there is no Client-initiated token request in push mode, there is no opportunity to present an `actor_token` at issuance time; the actor binding relies entirely on the upfront validation during the CIBA authentication request.

## A.8. CIBA Actor Token Continuity

The `auth_req_id` returned by the CIBA authentication response serves as the secure handle that carries the validated actor binding through the entire transaction lifecycle. Because the Delegated Actor's identity is bound to the `auth_req_id` at initiation time, subsequent token endpoint requests (poll and ping modes) or server-initiated token delivery (push mode) SHOULD NOT require the `actor_token` to be re-submitted. The `auth_req_id` itself provides the continuity guarantee.

If the Authorization Server's policy requires a fresh proof-of-presence at the moment of token issuance (e.g., for high-assurance delegation scenarios), the Authorization Server MUST advertise this requirement and the Client MUST include the `actor_token` in the token request. In push mode, where no Client-initiated token request occurs, fresh proof-of-presence cannot be enforced at issuance time; therefore, push mode SHOULD NOT be used for delegation scenarios requiring token-issuance-time actor proof-of-presence.

## A.9. CIBA Error Codes

The following additional error codes apply when CIBA is used:

invalid_binding_message:
: The `binding_message` does not accurately reflect the requested permissions. Applicable at the CIBA endpoint only.

expired_token:
: The `auth_req_id` has expired before the Granting User responded. Applicable during CIBA token delivery.

## A.10. CIBA Security Considerations

When CIBA {{OpenID.CIBA}} is used, the security considerations in Section 13 of {{OpenID.CIBA}} apply. In addition, the following delegation-specific considerations apply:

* **Out-of-Band Channel Security:** The out-of-band channel MUST be secured against interception and replay per Section 13.1 of {{OpenID.CIBA}}.
* **Binding Message Authenticity:** The `binding_message` is the Granting User's primary means of understanding the delegation. Compromise of this message could lead to unauthorized delegation.
* **Polling Rate Limiting:** In poll mode, the Authorization Server MUST enforce the `interval` parameter per Section 10 of {{OpenID.CIBA}}.
* **Callback Endpoint Security (Ping and Push):** Callback endpoints MUST be pre-registered, TLS-protected, and authenticated via `client_notification_token` per Sections 11 and 12 of {{OpenID.CIBA}}. In push mode, compromise of the callback would expose delegation tokens.
* **Push Mode Actor Binding:** In push mode, fresh `actor_token` proof-of-presence cannot be enforced at issuance time. Push mode SHOULD NOT be used for delegation scenarios requiring actor proof-of-presence at token issuance.

## A.11. CIBA Example: Automated Financial Portfolio Rebalancing

**Scenario:** An investor ("Bob") uses a brokerage platform ("InvestCo") that offers an automated portfolio rebalancing feature. A server-side script ("rebalancer-conservative-v1") periodically analyzes Bob's portfolio and executes trades to maintain his target allocation. This script is not an AI agent -- it is a traditional deterministic algorithm.

### A.11.1. Step 1: Delegated Actor Signals Intent

The rebalancing script (the Delegated Actor, identifier: `rebalancer-conservative-v1`) signals to the InvestCo platform (the Client) that it needs to read Bob's portfolio and execute trades using a conservative rebalancing strategy.

### A.11.2. Step 2: Client Attempts Action

InvestCo makes a request to the brokerage API (the Resource Server):

~~~
GET /api/portfolio/positions HTTP/1.1
Host: brokerage-api.example.com
Authorization: Bearer <existing_token>
~~~

### A.11.3. Step 3: Resource Server Challenge

The brokerage API determines the token lacks the required delegation claims for the rebalancing actor and responds:

~~~
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
  error_description="Token does not authorize automated trading",
  required_scope="read:portfolio execute:trades"
~~~

### A.11.4. Step 4: Dynamic Consent via CIBA (Out-of-Band)

Because the rebalancer operates as a background process and Bob is not actively using InvestCo, InvestCo initiates a CIBA authentication request with the rebalancer's `actor_token` for upfront validation:

~~~
POST /bc-authorize HTTP/1.1
Host: auth.investco.example.com
Content-Type: application/x-www-form-urlencoded

scope=read:portfolio execute:trades intent:rebalance:conservative&
client_id=investco-platform&
login_hint=bob@example.com&
binding_message=Allow rebalancer-v1 to rebalance your portfolio (conservative)&
requested_actor=rebalancer-conservative-v1&
actor_token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

The Authorization Server validates the `actor_token`, confirms `rebalancer-conservative-v1` is recognized, and returns:

~~~json
{
  "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
  "expires_in": 120,
  "interval": 5
}
~~~

### A.11.5. Step 5: Out-of-Band User Consent

Bob receives a push notification displaying the `binding_message`, the Delegated Actor identity, and the requested permissions. Bob reviews and taps "Authorize."

### A.11.6. Step 6: Token Polling

InvestCo polls the token endpoint per the CIBA poll mode. The `auth_req_id` carries the validated actor binding, so the `actor_token` is not re-submitted:

~~~
POST /token HTTP/1.1
Host: auth.investco.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:openid:params:grant-type:ciba&
auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1&
client_id=investco-platform
~~~

The Authorization Server returns `authorization_pending` until Bob responds.

### A.11.7. Step 7: Delegated Access Token Issued

Once Bob approves, the Authorization Server resolves the `auth_req_id` and issues the delegated Access Token.

Decoded JWT payload of the access token:

~~~json
{
  "iss": "https://auth.investco.example.com",
  "aud": "https://brokerage-api.example.com",
  "sub": "bob@example.com",
  "azp": "investco-platform",
  "scope": "read:portfolio execute:trades intent:rebalance:conservative",
  "exp": 1746009896,
  "iat": 1746006296,
  "jti": "tok-fin-9d4e",
  "act": {
    "sub": "rebalancer-conservative-v1"
  }
}
~~~

### A.11.8. Step 8: Action Completed

InvestCo retries the portfolio request with the new token. The brokerage API validates the `act` claim, confirms that `rebalancer-conservative-v1` is an authorized trading actor, and processes the portfolio read. The rebalancer script analyzes the positions, computes the necessary trades, and submits them through InvestCo using the same delegated token.

# Appendix B. Direct Authorization Code Grant Mode {#direct-appendix}

This appendix describes how the delegation parameters and semantics defined in this specification apply to the standard OAuth 2.0 Authorization Code Grant {{RFC6749}} when PAR is not available. This mode is retained as a baseline for low-complexity or legacy deployments.

## B.1. Differences from PAR Mode

The Direct Authorization Code Grant mode differs from the PAR-based flow in the following ways:

1. **No back-channel parameter submission:** Authorization parameters are transmitted through the Granting User's user-agent via query parameters, rather than submitted server-to-server to the PAR endpoint.

2. **No upfront `actor_token` validation:** The `actor_token` MUST NOT be included in the front-channel authorization request to avoid exposing it in the user-agent. The `actor_token` is only presented at the token endpoint. As with the PAR-based flow, the authorization request proceeds with the `requested_actor` identifier alone, and the Delegated Actor's cryptographic authentication occurs at the token endpoint.

3. **No `request_uri`:** The Client redirects the Granting User directly to the authorization endpoint with all parameters in the query string, rather than using a `request_uri`.

4. **Reduced request integrity:** Because parameters are transmitted through the user-agent, they are susceptible to tampering by browser extensions, malicious scripts, or compromised user-agents.

## B.2. Direct Authorization Request

~~~
GET /authorize?response_type=code&client_id=<client_id>&redirect_uri=<redirect_uri>&scope=<scope>&state=<state>&code_challenge=<code_challenge>&code_challenge_method=S256&requested_actor=<actor_id> HTTP/1.1
Host: authorization-server.example.com
~~~

## B.3. Request Parameters

All parameters defined in Section 4.4 of the main specification apply to the direct authorization request, with the following exceptions:

actor_token:
: MUST NOT be included. The `actor_token` MUST NOT be transmitted through the user-agent to avoid exposure. It is only presented at the token endpoint.

actor_token_type:
: MUST NOT be included. Only applicable when `actor_token` is present.

## B.4. Authorization Server Processing (Direct)

Upon receiving the authorization request, the Authorization Server MUST perform the following steps:

1. Validate the request parameters according to the OAuth 2.0 Authorization Code Grant (Section 4.1.1 of {{RFC6749}}).

2. Record the `requested_actor` value and bind it to the authorization session. The Authorization Server MAY optionally validate the `requested_actor` against a registry of known Delegated Actor identities if one is maintained, and MAY reject the request with the error code `invalid_actor` if the actor has been explicitly blocked by policy. However, pre-registration of actor identities is NOT REQUIRED; the Authorization Server MAY accept any `requested_actor` value, deferring authoritative actor authentication to the token endpoint where the `actor_token` is mandatory.

3. The Authorization Server MUST present a consent screen to the Granting User per the consent screen requirements defined in Section 4.7 of the main specification.

If the request is valid and the Granting User grants consent, the Authorization Server proceeds to issue an Authorization Code. If the Granting User denies consent, the Authorization Server MUST return an error response with the error code `authorization_denied`. If the request is invalid, the Authorization Server returns an appropriate error response.

## B.5. Authorization Response and Token Exchange

The Authorization Code Response and the Token Request follow the same format as defined in Section 5 and Section 6 of the main specification. The Client MUST include the `actor_token` at the token endpoint. The Authorization Server MUST verify that the `actor_token`'s `sub` claim matches the `requested_actor` bound to the Authorization Code. Since no upfront `actor_token` validation occurs in direct mode, this token endpoint validation is the sole point of Delegated Actor authentication.

## B.6. Direct Mode Example: Simple Task Automation

**Scenario:** A user ("Carol") uses a lightweight task management application ("TaskLite") that integrates with a simple automation script ("auto-archiver-v1"). Carol asks the script to archive completed tasks from her project board.

### B.6.1. Step 1: Delegated Actor Signals Intent

The automation script (the Delegated Actor, identifier: `auto-archiver-v1`) signals to TaskLite (the Client) that it needs to read Carol's tasks and archive completed ones.

### B.6.2. Step 2: Client Attempts Action

TaskLite makes a request to Carol's project board service (the Resource Server):

~~~
GET /api/tasks?status=completed HTTP/1.1
Host: projects.example.com
Authorization: Bearer <existing_token_without_act_claim>
~~~

### B.6.3. Step 3: Resource Server Challenge

The project board service determines the token lacks the required delegation claims and responds:

~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  error_description="Access token missing required delegation claims"
~~~

### B.6.4. Step 4: Dynamic Consent via Direct Authorization Request

Because TaskLite is a simple application and the Authorization Server does not support PAR, TaskLite constructs a direct authorization request:

~~~
GET /authorize?response_type=code&client_id=tasklite-app&redirect_uri=https://tasklite.example.com/callback&scope=read:tasks write:tasks intent:archive_completed&state=abc123&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256&requested_actor=auto-archiver-v1 HTTP/1.1
Host: auth.example.com
~~~

Note: The `actor_token` is NOT included in this front-channel request.

### B.6.5. Step 5: Granting User Consent

The Authorization Server authenticates Carol and displays a consent screen:

> **TaskLite** is requesting that **auto-archiver-v1** be allowed to act on your behalf:
>
> - **Read** your tasks
> - **Modify** your tasks
>
> **Purpose:** Archive completed tasks
>
> [Allow]  [Deny]

Carol clicks "Allow."

### B.6.6. Step 6: Authorization Code Issued

~~~
HTTP/1.1 302 Found
Location: https://tasklite.example.com/callback?code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf&state=abc123
~~~

### B.6.7. Step 7: Token Exchange with Actor Authentication

TaskLite exchanges the code at the token endpoint, including the `actor_token` for the first time:

~~~
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
client_id=tasklite-app&
code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
redirect_uri=https://tasklite.example.com/callback&
actor_token=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

### B.6.8. Step 8: Delegated Access Token Issued

~~~json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:tasks write:tasks intent:archive_completed"
}
~~~

Decoded JWT payload of the access token:

~~~json
{
  "iss": "https://auth.example.com",
  "aud": "https://projects.example.com",
  "sub": "carol@example.com",
  "azp": "tasklite-app",
  "scope": "read:tasks write:tasks intent:archive_completed",
  "exp": 1746009896,
  "iat": 1746006296,
  "jti": "tok-task-a3b4",
  "act": {
    "sub": "auto-archiver-v1"
  }
}
~~~

### B.6.9. Step 9: Action Completed

TaskLite retries the request with the new token. The project board service validates the `act` claim and processes the request. The auto-archiver script reads the completed tasks and archives them.

# Appendix C. Consent Scope Prefix Convention {#consent-scope-prefix}

## C.1. Overview

This appendix provides a RECOMMENDED convention for encoding the Delegated Actor's intended action or purpose within the standard OAuth 2.0 `scope` parameter, rather than introducing a separate parameter. By using a well-known prefix on scope values, deployments can distinguish resource-permission scopes (e.g., `read:calendar`) from consent-descriptive scopes that convey the purpose of the delegation (e.g., `intent:schedule_meeting`).

This convention is OPTIONAL. Deployments that adopt it gain enhanced consent presentation and downstream policy enforcement without requiring protocol extensions beyond those defined in the normative sections of this specification.

## C.2. Prefix Convention

Deployments SHOULD use a registered prefix to distinguish consent scopes from resource-permission scopes. The RECOMMENDED prefix is `intent:`. For example:

* `intent:schedule_meeting` -- Indicates the Delegated Actor intends to schedule a meeting.
* `intent:rebalance_portfolio:conservative` -- Indicates the Delegated Actor intends to rebalance a portfolio using a conservative strategy.
* `intent:send_weekly_report` -- Indicates the Delegated Actor intends to compile and send a weekly report.

These prefixed scope values are included alongside standard resource-permission scopes in the `scope` parameter:

~~~
scope=read:calendar write:calendar intent:schedule_meeting
~~~

Deployments MAY define their own prefix (e.g., `action:`, `purpose:`, or a URN-based prefix such as `urn:example:intent:`) provided the prefix is consistently recognized by the Authorization Server and Resource Servers within the deployment.

## C.3. Authorization Server Behavior

When the Authorization Server receives a scope value with a recognized consent-scope prefix, it SHOULD:

1. **Parse and separate** the prefixed consent scopes from the resource-permission scopes.

2. **Resolve** each consent scope to a human-readable description, if a registered description is available (e.g., `intent:schedule_meeting` resolves to "Schedule a meeting on your behalf").

3. **Present** the resolved description on the consent screen in addition to the resource-permission scopes. This gives the Granting User a clear understanding of both *what the Delegated Actor intends to do* and *which resource permissions are required to do it*.

4. **Record** the granted consent scopes (both resource-permission and consent-descriptive) in the issued Access Token's `scope` claim, so the full intent is available for downstream validation.

If the Authorization Server does not recognize a prefixed scope value, it SHOULD treat it as an opaque scope value per standard OAuth 2.0 behavior.

## C.4. Resource Server Behavior

Resource Servers receiving an Access Token that contains consent-scope prefixed values SHOULD:

1. **Validate** the resource-permission scopes as usual to determine whether the bearer has sufficient permissions for the requested operation.

2. **Inspect** any consent-scope values (e.g., those matching the `intent:` prefix) to verify that the action being performed is consistent with the stated intent. For example, if the token contains `intent:schedule_meeting` but the request is to delete a calendar, the Resource Server SHOULD reject the request even if `write:calendar` is present.

3. **Log** the consent-scope values alongside the `act` claim for audit purposes, providing a record of what the Delegated Actor was authorized to do and what it actually attempted.

This approach enables Resource Servers to enforce intent-based policies without requiring a separate protocol parameter or token claim.

## C.5. Example

A Client requesting delegation for an AI assistant to schedule a meeting submits the following PAR request:

~~~
POST /par HTTP/1.1
Host: authorization-server.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code&
client_id=workhub-app&
redirect_uri=https://workhub.example.com/callback&
scope=read:calendar write:calendar intent:schedule_meeting&
code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
code_challenge_method=S256&
requested_actor=assistbot-v2&
actor_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&
actor_token_type=urn:ietf:params:oauth:token-type:jwt
~~~

The Authorization Server parses the `scope` parameter and identifies:

* Resource-permission scopes: `read:calendar`, `write:calendar`
* Consent scope: `intent:schedule_meeting` resolves to "Schedule a meeting on your behalf"

The consent screen presented to the Granting User displays:

~~~
WorkHub is requesting that AssistBot (assistbot-v2) act on your behalf:

  Purpose: Schedule a meeting on your behalf
  Permissions: Read your calendar, Write to your calendar

  [Allow]  [Deny]
~~~

The resulting Access Token includes all granted scopes:

~~~json
{
  "iss": "https://authorization-server.example.com",
  "sub": "alice",
  "azp": "workhub-app",
  "scope": "read:calendar write:calendar intent:schedule_meeting",
  "act": {
    "sub": "assistbot-v2"
  }
}
~~~

The Resource Server (calendar API) validates that:

1. `read:calendar` and `write:calendar` are present (sufficient permissions).
2. `intent:schedule_meeting` is consistent with the calendar write operation being attempted.
3. The `act.sub` identifies a recognized Delegated Actor.

# Appendix D. Actor Representation and Actor Token Acquisition {#actor-token-acquisition}

This appendix provides RECOMMENDED guidance on how a Delegated Actor establishes its identity and obtains an Actor Token for use in the delegation flows defined by this specification. The normative sections of this specification treat the Actor Token as an opaque input: a JWT {{RFC7519}} whose `sub` claim identifies the Delegated Actor. This appendix describes the ecosystem of identity models, token claims, and token acquisition mechanisms that produce such tokens.

This appendix is designed to be compatible with a broad range of existing and emerging identity standards. While current deployments typically rely on OAuth 2.0 client credentials and platform-issued workload tokens, this specification anticipates future identity frameworks for autonomous software entities -- including workload identity standards, verifiable credentials, decentralized identifiers, and agent-specific identity protocols -- and provides extensibility points to accommodate them without requiring changes to the normative protocol.

## D.1. Actor Identity Models

A Delegated Actor MUST possess a stable, unique identity that can be represented as the `sub` claim in a JWT. The identity model used to represent a Delegated Actor is independent of the delegation protocol defined in this specification; any model that can produce a JWT with a unique `sub` claim is compatible. The following identity models are RECOMMENDED but this list is not exhaustive:

### D.1.1. OAuth 2.0 Client Identity

The Delegated Actor is registered as an OAuth 2.0 client with its own `client_id` and credentials at an identity provider. This is the most straightforward model: the actor authenticates using the OAuth 2.0 Client Credentials Grant (Section 4.4 of {{RFC6749}}) or Mutual TLS Client Authentication ({{?RFC8705}}) to obtain a JWT that serves as its Actor Token.

This model is suitable for:

* AI agents or automation services that are deployed as standalone applications with their own client registrations.
* Background services and batch-processing scripts that operate under a fixed application identity.

### D.1.2. Service Account Identity

The Delegated Actor operates under a service account -- a non-human account provisioned in an identity provider's user directory or service registry. The service account has its own credentials (e.g., a client secret, a certificate, or a key pair) and authenticates to the identity provider to obtain a JWT with a `sub` claim corresponding to the service account identifier.

This model is suitable for:

* Robotic process automation (RPA) bots that are provisioned as named service accounts within an organization's identity infrastructure.
* IT support technicians or human operators modeled as service accounts when acting in a delegated capacity (see the human-actor discussion in Section 1).
* Internal microservices that need to act on behalf of users and are identified by service account names.

### D.1.3. Workload Identity

The Delegated Actor is identified by a workload identity -- a platform-assigned identity bound to a specific compute workload (e.g., a Kubernetes pod, a cloud function, a virtual machine instance, or a container). The workload obtains its identity token from the platform's identity service (e.g., a cloud provider's instance metadata service or a service mesh identity issuer) without requiring static credentials to be provisioned or rotated by an administrator.

Workload identity standards such as SPIFFE (Secure Production Identity Framework for Everyone) provide a uniform identity namespace (`spiffe://<trust-domain>/<workload-path>`) and verifiable identity documents (SVIDs) that can be used as the basis for an Actor Token. The IETF Workload Identity in Multi-System Environments (WIMSE) working group is standardizing JWT-based workload identity tokens and cross-system trust establishment; tokens produced by WIMSE-compliant systems are directly compatible with the Actor Token format defined in this specification.

This model is suitable for:

* Cloud-native AI agents and automation services running in managed environments where the platform attests to the workload's identity.
* Ephemeral or auto-scaled services where static client credentials are impractical to manage.
* Zero-trust architectures where identity is bound to the runtime environment rather than to a pre-provisioned secret.
* Multi-system environments where workloads need a portable, verifiable identity across trust boundaries.

### D.1.4. Autonomous Agent Identity

The Delegated Actor is an autonomous software agent -- such as an AI agent, an AI orchestrator coordinating sub-agents, or a long-running decision-making process -- that requires a distinct identity reflecting its autonomous nature. Unlike traditional OAuth clients or service accounts that represent a fixed application, autonomous agents may have dynamic characteristics: they may be instantiated on demand, composed from multiple sub-components, versioned independently of the hosting platform, or identified by both a persistent agent type and an ephemeral instance identifier.

The autonomous agent identity model supports the following patterns:

Persistent Agent Type Identity:
: The agent has a stable identity representing the agent type or product (e.g., `assistbot-v2`, `financial-advisor-agent`). This identity persists across instantiations and is used as the `sub` claim. This approach is RECOMMENDED when the Authorization Server and Resource Server need to apply consistent policies to a class of agents regardless of which specific instance is running.

Ephemeral Instance Identity:
: Each agent instance receives a unique, short-lived identity from a platform or orchestration layer (e.g., `agent-instance-a1b2c3`). The `sub` claim identifies the specific instance. This approach is suitable for environments with strict audit requirements where actions must be traceable to individual agent instances.

Composite Agent Identity:
: An orchestrator agent delegates tasks to sub-agents, each with their own identity. The orchestrator's Actor Token identifies the top-level agent, and sub-agent identities MAY be represented through additional claims or through nested delegation chains using the `act` claim as defined in {{RFC8693}}. Authorization Servers MAY enforce policies on the maximum delegation depth.

This model is suitable for:

* AI agent frameworks where agents are instantiated, versioned, and retired dynamically.
* Multi-agent systems where an orchestrator coordinates specialized sub-agents.
* Agent marketplaces or registries where agents are catalogued with stable identifiers and metadata.

## D.2. Actor Token Claims

The normative sections of this specification require only the `sub` claim to identify the Delegated Actor. However, to support richer authorization policies, interoperability across identity systems, and forward compatibility with emerging autonomous agent standards, Actor Tokens MAY include additional claims. This section defines a set of RECOMMENDED claims and provides guidance on extending the Actor Token with custom claims.

### D.2.1. Core Claims

The following claims are defined by the JWT specification {{RFC7519}} and MUST or SHOULD be present in an Actor Token:

`iss` (Issuer):
: REQUIRED. The identifier of the entity that issued the Actor Token.

`sub` (Subject):
: REQUIRED. A unique identifier for the Delegated Actor. This is the primary claim used by the Authorization Server to identify the actor. The `sub` value MUST be stable for a given actor identity within the scope of the issuer.

`aud` (Audience):
: RECOMMENDED. The identifier of the intended recipient (typically the Authorization Server). Including `aud` prevents token replay across unrelated systems.

`exp` (Expiration Time):
: REQUIRED. The time after which the Actor Token MUST NOT be accepted.

`iat` (Issued At):
: RECOMMENDED. The time at which the Actor Token was issued.

`jti` (JWT ID):
: RECOMMENDED. A unique identifier for the token, enabling replay detection.

### D.2.2. Actor Metadata Claims

The following OPTIONAL claims provide additional context about the Delegated Actor. Authorization Servers and Resource Servers MAY use these claims for policy decisions, audit logging, and consent display. These claims are advisory and non-normative; their interpretation is deployment-specific.

`actor_type`:
: A string indicating the category of the Delegated Actor. Deployments SHOULD use values from a controlled vocabulary appropriate to their domain. Example values include `ai_agent`, `rpa_bot`, `background_service`, `orchestrator`, and `human_operator`. This claim enables Authorization Servers to apply type-specific policies (e.g., requiring additional consent for AI agents, or restricting certain scopes to human operators).

`version`:
: A string indicating the version of the software or model. This claim supports deployments that apply version-specific authorization policies or audit trails (e.g., `2.1.0`, `gpt-4o-2024-05-13`).

`capabilities`:
: An array of strings describing the high-level capabilities or functions the agent is designed to perform (e.g., `["calendar_management", "email_drafting", "data_analysis"]`). Resource Servers MAY use this claim to validate that the agent's declared capabilities are consistent with the requested scopes.

`instance_id`:
: A string uniquely identifying a specific running instance of the software entity. When the `sub` claim represents a persistent agent type identity, this claim distinguishes individual instances for audit and tracing purposes.

`trust_framework`:
: A string or URI identifying the trust framework under which the actor's identity was established (e.g., `urn:ietf:params:oauth:trust-framework:wimse`, `https://spiffe.io`, or a deployment-specific value). This claim enables Authorization Servers to determine the applicable validation rules for the Actor Token.

### D.2.3. Actor Token Example with Metadata Claims

The following is a non-normative example of an Actor Token that includes both core and metadata claims:

~~~json
{
  "iss": "https://actor-idp.example.com",
  "sub": "assistbot-v2",
  "aud": "https://authorization-server.example.com",
  "exp": 1746009896,
  "iat": 1746006296,
  "jti": "actor-tok-9f3a",
  "actor_type": "ai_agent",
  "version": "2.1.0",
  "capabilities": ["calendar_management", "email_drafting"],
  "instance_id": "inst-7c4e2f",
  "trust_framework": "https://actor-idp.example.com/trust-policy"
}
~~~

### D.2.4. Claim Extensibility

Deployments MAY define additional claims in the Actor Token to carry domain-specific metadata. To avoid collisions with future standardized claims, custom claim names SHOULD use a namespace prefix following the collision-resistant naming conventions defined in Section 4.2 of {{RFC7519}} (e.g., `https://example.com/claims/risk_score`). The Authorization Server MUST ignore unrecognized claims that it does not understand, ensuring forward compatibility when new claims are introduced by future specifications.

Identity standards that define their own claim sets (e.g., workload identity claims from WIMSE, verifiable credential status claims from W3C Verifiable Credentials) MAY be included in the Actor Token alongside the core claims defined above. The `trust_framework` claim SHOULD be used to signal to the Authorization Server which additional claims are present and how they should be interpreted.

## D.3. Obtaining the Actor Token

Regardless of the identity model, the Delegated Actor MUST obtain a JWT to use as its Actor Token. The following mechanisms are RECOMMENDED:

### D.3.1. Client Credentials Grant

The Delegated Actor authenticates to the token endpoint of its identity provider using the OAuth 2.0 Client Credentials Grant (Section 4.4 of {{RFC6749}}). The identity provider issues a JWT access token (or a dedicated identity assertion) whose `sub` claim identifies the Delegated Actor.

### D.3.2. Mutual TLS (mTLS) Client Authentication

The Delegated Actor authenticates using a client certificate bound to its identity, per {{?RFC8705}}. The identity provider validates the certificate chain and issues a JWT whose `sub` claim is derived from the certificate's subject or Subject Alternative Name (SAN). This approach eliminates shared secrets and provides strong cryptographic proof of the actor's identity.

### D.3.3. JWT Assertion (private_key_jwt)

The Delegated Actor creates and signs a JWT assertion using its private key, per Section 2.2 of {{?RFC7523}}, and presents it to the identity provider's token endpoint. The identity provider validates the assertion's signature against the actor's pre-registered public key and issues an Actor Token in response. This mechanism is RECOMMENDED for Delegated Actors that manage their own key pairs.

### D.3.4. Platform-Issued Workload Tokens

In cloud and container-orchestrated environments, the Delegated Actor obtains an identity token directly from the platform's identity service (e.g., a cloud provider's instance metadata endpoint, a Kubernetes service account token projection, or a SPIFFE-compliant identity issuer such as SPIRE). The platform-issued token is a JWT attesting to the workload's identity. The Delegated Actor MAY use this token directly as its Actor Token if the Authorization Server trusts the platform issuer, or MAY exchange it for an Actor Token via a token exchange ({{RFC8693}}) with a trusted identity provider.

When the platform issues SPIFFE Verifiable Identity Documents (SVIDs) in JWT format, the SVID's `sub` claim (containing the SPIFFE ID) can serve directly as the Delegated Actor's identifier. Similarly, workload identity tokens produced by WIMSE-compliant systems carry standardized claims that make them suitable for direct use as Actor Tokens or as source tokens in a token exchange.

### D.3.5. Verifiable Credential Presentation

In environments that adopt W3C Verifiable Credentials, a Delegated Actor MAY prove its identity by presenting a Verifiable Credential (VC) issued by a trusted authority. The identity provider (or the Authorization Server itself) verifies the credential's cryptographic proof and issues a JWT Actor Token whose `sub` claim is derived from the credential subject identifier. The `trust_framework` claim in the resulting Actor Token SHOULD indicate the Verifiable Credentials trust model under which the identity was established.

This mechanism is suitable for:

* Decentralized identity environments where agent identities are issued as Verifiable Credentials by multiple independent authorities.
* Agent marketplace scenarios where an agent's identity credential is portable across different platforms and Authorization Servers.
* Scenarios requiring selective disclosure, where the agent reveals only the claims necessary for a specific authorization decision.

The Delegated Actor MAY present Verifiable Credentials using the OpenID for Verifiable Presentations (OID4VP) protocol to the identity provider's token endpoint, which then issues an Actor Token based on the verified credential claims.

### D.3.6. Token Exchange for Composed Identities

In multi-agent or multi-tier deployments, a Delegated Actor MAY obtain its Actor Token by exchanging an existing identity token for a new token scoped to the current delegation context. The OAuth 2.0 Token Exchange framework ({{RFC8693}}) supports this pattern: the Delegated Actor presents a platform-issued workload token, a Verifiable Credential-derived token, or another identity assertion as the `subject_token`, and receives a JWT Actor Token in return.

This mechanism is suitable for:

* Orchestrator agents that receive a platform identity at startup and exchange it for a more specific Actor Token that carries the orchestrator's agent-level identity and metadata claims.
* Agents migrating between runtime environments (e.g., from one cloud region to another) that need to re-establish their identity with a local identity provider while retaining a stable `sub` identifier.
* Bridging between heterogeneous identity systems -- for example, exchanging a SPIFFE SVID or a WIMSE workload token for an Actor Token accepted by an Authorization Server that does not natively understand those identity formats.

## D.4. Actor Token Issuer Trust

The Actor Token presented in the delegation flow is validated by the Authorization Server. The issuer of the Actor Token -- the identity provider that authenticated the Delegated Actor -- MAY or MAY NOT be the same entity as the Authorization Server that authenticates the Granting User.

### D.4.1. Same-Issuer Model

When the Actor Token issuer is the same Authorization Server that processes the delegation flow, trust is implicit. The Authorization Server validates the Actor Token using its own signing keys and token policies. This is the simplest deployment model and is RECOMMENDED when all parties (Granting Users, Clients, and Delegated Actors) are managed within a single identity domain.

### D.4.2. Cross-Issuer Model

When the Actor Token is issued by a different identity provider than the Authorization Server, the Authorization Server MUST establish trust in the external issuer. The following mechanisms are RECOMMENDED:

Pre-Configured Trust:
: The Authorization Server is configured with a list of trusted Actor Token issuers, including each issuer's identifier (`iss` value) and its public key material or JWKS endpoint URI. The Authorization Server validates Actor Tokens from these issuers by fetching their signing keys (e.g., via the issuer's `jwks_uri` from its OpenID Connect Discovery metadata document) and verifying the token's signature, issuer, and audience claims. This is the RECOMMENDED approach for stable, known partnerships between organizations.

Dynamic Issuer Verification:
: The Authorization Server dynamically resolves an unknown Actor Token issuer by retrieving the issuer's OpenID Connect Discovery metadata (`.well-known/openid-configuration`) from the `iss` claim in the Actor Token. The Authorization Server fetches the issuer's JWKS and validates the token's signature. To prevent abuse, the Authorization Server MUST maintain an allowlist of permitted issuer domains or apply rigorous validation policies (e.g., requiring the issuer to be within a specific domain suffix, validating the issuer's TLS certificate chain, or requiring prior administrative approval before accepting tokens from a newly discovered issuer). Dynamic verification without any form of allowlist or domain restriction is NOT RECOMMENDED due to the risk of accepting tokens from attacker-controlled issuers.

Federation Protocols:
: In federated environments, the Authorization Server MAY rely on an established federation framework (e.g., OpenID Federation) to dynamically discover and validate trust relationships with external Actor Token issuers. The federation trust chain provides the cryptographic assurance that the issuer is a legitimate participant in the federation.

Workload Identity Federation:
: When the Actor Token originates from a workload identity system (e.g., SPIFFE, a cloud provider's workload identity service, or a WIMSE-compliant issuer), the Authorization Server MAY establish trust through workload-specific federation mechanisms. This includes trusting a SPIFFE trust bundle for a given trust domain, accepting signed metadata from a WIMSE token service, or configuring trust in a cloud provider's workload identity issuer. The Authorization Server SHOULD validate that the workload identity token's claims (e.g., SPIFFE ID namespace, workload attributes) conform to the expected trust policy.

### D.4.3. Recommendations

1. The Authorization Server MUST validate the Actor Token's signature, `iss`, `sub`, `aud` (if present), and `exp` claims regardless of whether the issuer is the same or different entity.

2. When the Actor Token issuer is external, the Authorization Server SHOULD require that the Actor Token's `aud` claim includes the Authorization Server's identifier, to prevent token replay across unrelated Authorization Servers.

3. The Authorization Server SHOULD cache issuer metadata and JWKS responses according to their HTTP cache headers to avoid excessive network calls during token validation.

4. Deployments SHOULD document which Actor Token issuers are trusted and the mechanism by which trust is established (pre-configured, dynamic, federated, or workload identity federation) in the Authorization Server's operational documentation.

5. When validating Actor Tokens that contain metadata claims (Section D.2.2), the Authorization Server MUST NOT reject tokens solely because they contain unrecognized claims. This ensures forward compatibility as new identity standards introduce additional claims.

## D.5. Interoperability with External Identity and Agent Standards

This specification is intentionally decoupled from any specific identity framework beyond the requirement that the Actor Token be a JWT with a `sub` claim. This design enables interoperability with a wide range of existing and emerging standards. This section provides guidance on how specific external standards can be integrated with the Actor Token model.

### D.5.1. SPIFFE and Workload Identity Standards

The Secure Production Identity Framework for Everyone (SPIFFE) defines a standard for identifying and securing workloads across heterogeneous environments. SPIFFE Verifiable Identity Documents (SVIDs) in JWT format are directly compatible with the Actor Token format: the `sub` claim carries the SPIFFE ID (e.g., `spiffe://trust-domain/workload-path`), and the `iss` claim identifies the SPIFFE trust domain's identity provider.

The IETF WIMSE (Workload Identity in Multi-System Environments) working group is developing standards for workload identity tokens that traverse trust boundaries. WIMSE workload identity tokens are JWT-based and are designed to carry workload-specific claims (e.g., workload attributes, trust domain, security posture) that complement the Actor Token claims defined in Section D.2. Authorization Servers deploying this specification in environments with WIMSE-compliant infrastructure SHOULD accept WIMSE workload identity tokens as Actor Tokens when the issuing trust domain is trusted.

### D.5.2. W3C Verifiable Credentials and Decentralized Identifiers

W3C Verifiable Credentials (VCs) provide a standard for cryptographically verifiable claims about a subject, and Decentralized Identifiers (DIDs) provide a method for creating globally unique, self-sovereign identifiers. Together, they enable an identity model where a Delegated Actor's identity is not tied to any single centralized identity provider.

To integrate with this specification:

* An agent's DID serves as the stable `sub` claim in the Actor Token.
* A Verifiable Credential issued to the agent by a trusted authority attests to the agent's properties (type, capabilities, authorized operations).
* The identity provider (or the Authorization Server) verifies the VC presentation and issues a JWT Actor Token, or the VC itself is exchanged for an Actor Token via the token exchange mechanism described in Section D.3.6.
* The `trust_framework` claim (Section D.2.2) SHOULD be populated with a value indicating the VC trust model (e.g., a DID method or a VC issuer trust registry).

This integration path allows deployments to adopt decentralized agent identity incrementally, without changes to the normative delegation protocol.

### D.5.3. Agent Communication Protocols

Emerging agent communication protocols -- such as the Model Context Protocol (MCP), the Agent-to-Agent Protocol (A2A), and similar frameworks -- define their own conventions for agent identification and capability discovery. When a Delegated Actor participates in such a protocol alongside the delegation flows defined in this specification, the following guidance applies:

* The agent's identifier within the agent communication protocol SHOULD be consistent with the `sub` claim in its Actor Token, to enable correlation of authorization decisions with agent protocol interactions.
* Agent capability metadata defined by the communication protocol MAY be reflected in the Actor Token's `agent_capabilities` claim (Section D.2.2) to allow Authorization Servers to make capability-aware authorization decisions.
* Deployments that bridge between agent communication protocols and OAuth-based authorization SHOULD document the mapping between the agent protocol's identity model and the Actor Token's `sub` claim to avoid ambiguity.

This specification does not mandate the use of any specific agent communication protocol. The Actor Token model is protocol-agnostic: any agent framework that can produce or consume JWT-based identity assertions is compatible.

### D.5.4. Forward Compatibility

This specification is designed to accommodate identity standards that do not yet exist. The following principles ensure forward compatibility:

1. The Actor Token format is extensible through custom JWT claims (Section D.2.4). New identity standards MAY define additional claims without requiring changes to the normative protocol.

2. The `trust_framework` claim (Section D.2.2) provides a signaling mechanism for Authorization Servers to determine which identity standard produced the Actor Token and which validation rules apply.

3. The token exchange mechanism (Section D.3.6) serves as a universal bridge: identity assertions from any format or framework can be exchanged for a compliant JWT Actor Token, as long as a trusted identity provider mediates the exchange.

4. The Authorization Server's trust configuration (Section D.4) supports pluggable trust models -- from simple pre-configured trust lists to dynamic federation -- enabling new trust establishment mechanisms to be adopted without protocol changes.

5. Deployments SHOULD design their Authorization Server's Actor Token validation pipeline to be modular, so that new issuer types, claim sets, and trust frameworks can be added through configuration rather than code changes.
