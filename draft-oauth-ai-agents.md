---
title: "OAuth 2.0 for AI Agent Authorization"
abbrev: "OAuth 2.0 for AI Agent Authorization"
category: info

docname: draft-oauth-ai-agents
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: 
keyword:
 - ai-agents
 - authorization

author:
 -
    fullname: Thilina Shashimal Senarath
    organization: WSO2
    email: thilinasenarath97@gmail.com

normative:

informative:


--- abstract

This specification defines an extension to the OAuth 2.0 Authorization Framework [RFC6749] to enable autonomous agents to obtain delegated access tokens to act on behalf of users. It introduces a new authorization request parameter, `requested_agent`, and defines a custom grant type, `urn:ietf:params:oauth:grant-type:agent-authorization_code`, specifically designed to facilitate explicit user consent for an agent's actions and enable the agent to exchange an authorization code for a delegated access token using its own authentication credentials (an agent token). The extension ensures secure delegation, explicit user consent captured at the authorization server, and enhanced auditability through specific token claims that document the delegation path from the user to the agent acting via a client application.


--- middle

# Introduction

Autonomous agents are increasingly integrated into systems to perform tasks on behalf of users. These agents often require access to protected resources, necessitating a robust and secure authorization mechanism that accurately reflects the user's intent and the agent's role in the access request. Standard OAuth 2.0 flows, such as the Authorization Code Grant [RFC6749] and the Client Credentials Grant [RFC6749], do not fully address the nuances of agent delegation where explicit user consent for a specific agent's action is required and the agent itself acts as a distinct identity in the token exchange process. While the OAuth 2.0 Token Exchange specification [RFC8693] provides a mechanism for exchanging tokens, it typically focuses on inter-service communication or impersonation flows initiated server-side and doesn't inherently provide a mechanism for obtaining explicit user consent for an agent via the front channel initiated from the authorization endpoint.

This specification extends OAuth 2.0 to specifically support scenarios where a user delegates authority to an autonomous agent. It leverages the existing Authorization Code Grant flow by introducing mechanisms at the authorization endpoint to identify the specific agent for which delegation is sought and by defining a new grant type for the token endpoint that allows the agent to authenticate itself while presenting the user-approved authorization code. The resulting delegated access token explicitly records the identity of the user, the agent, and the client application involved, facilitating clear audit trails.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

# Terminology

This specification uses the following terms:

Agent: An autonomous software entity that acts on behalf of a user. An agent has a distinct identity and authentication credentials separate from the client application that might host or invoke it.
Agent Token: A security token (e.g., a JWT [RFC7519]) used by an agent to authenticate itself to the authorization server or resource servers. The sub claim of an agent token identifies the agent.
Delegated Access Token: An access token issued by the authorization server to an agent, granting it permission to access protected resources on behalf of a specific user. This token explicitly documents the delegation path.
User: The resource owner who grants consent for an agent to access their protected resources.
Client: An application that initiates the authorization flow and facilitates the interaction between the user, agent, and authorization server. This is the "client" as defined in OAuth 2.0 [RFC6749].
Authorization Server: The server that issues access tokens to the client and agent after successfully authenticating a resource owner and obtaining authorization.
Resource Server: The server hosting the protected resources, capable of accepting and validating delegated access tokens.   
Agent-Authorization Code: A temporary, single-use code issued by the authorization server to the client's redirect URI after the user has authenticated and granted consent for a specific agent to act on their behalf. This code is then provided to the agent.

# Preconditions

The AI agent holds a valid agent token, obtained via a separate process, which is not covered in this document. The agent token is used to authenticate the agent and authorize it to perform actions on its own behalf.


# Protocol Overview

This extension defines a flow where a client application facilitates user consent for an agent, and the agent then uses this consent along with its own authentication to obtain a delegated access token.

## High-Level Overview

(1) The client application initiates the flow by directing the user's user-agent to the Authorization Server's authorization endpoint, including a requested_agent parameter identifying the agent.

(2) The Authorization Server authenticates the user and presents a consent screen detailing the client, the requested agent, and the scopes.
Upon user consent, the Authorization Server issues a short-lived 

(3) Agent-Authorization Code tied to the user, client, and agent, and redirects the user-agent back to the client's redirect_uri.

(4) The client receives the Agent-Authorization Code (via the user-agent redirect). The client then typically passes this code to the agent.

(5) The agent requests a Delegated Access Token from the Authorization Server's token endpoint using the new `urn:ietf:params:oauth:grant-type:agent-authorization_code` grant type. This request includes the Agent-Authorization Code, the PKCE code_verifier, and the agent token.

(6) The Authorization Server validates the request, including verifying the Agent-Authorization Code, the PKCE code_verifier, and the Agent Token. It ensures the Agent Token corresponds to the requested_agent approved by the user.

(7) Upon successful validation, the Authorization Server issues a Delegated Access Token to the agent. This token is typically a JWT containing claims identifying the user (sub), the client (azp), and the agent (act claim).

## Sequence Diagram

~~~ ascii-art

+------------+          +--------+        +--------+        +--------------------+        +----------------+
| User-Agent |          | Client |        | Agent  |        | Authorization      |        | Resource       |
|            |          |        |        |        |        | Server             |        | Server         |
+------------+          +--------+        +--------+        +--------------------+        +----------------+
       |                     |                 |                       |                          |
       |                     |<----------------|                       |                          |
       |                     |  Request to act on behalf of user       |                          |
       |                     |---------------->|                       |                          |
       |   (A) Redirect to /authorize with requested_agent=<agent_id>  |                          |
       |-------------------------------------------------------------->|                          |
       |   (B) User authenticates and consents (show agent + scopes)   |                          |
       |<--------------------------------------------------------------|                          |
       |   (C) Redirect with Agent-Authorization Code                  |                          |
       |<--------------------------------------------------------------|                          |
       |                     |                                         |                          |
       |   (C) Agent-Authorization Code                                |                          |
       |-------------------------------------------------------------->|                          |
       |                     |   (E) POST /token (code + verifier + agent token)                  |
       |                     |---------------------------------------->|                          |
       |                     |   (F) Delegated Access Token (JWT)      |                          |
       |                     |<----------------------------------------|                          |
       |                     |                                         |                          |
       |                       (G) Access Resource with Delegated Access Token                    |
       |                     | ----------------------------------------->                         |
       |                     |                                         |   (H) Token validation   |
       |                     |                                         |------------------------->|
       |                     |                                         |<-------------------------|
       |                     |                                         |                          |
       |                     |       (G) Protected Resource Response   |                          |                      
       |                     |<-------------------------------------------------------------------|


~~~

(A): Agent requests to access protected resources on behalf of the user.
(B): Client initiates Authorization Request via user-agent, including requested_agent and PKCE challenge.
(C): User authenticates and grants consent for the specific agent and requested scopes at the Authorization Server.
(D): Authorization Server issues Agent-Authorization Code and redirects user-agent back to client.
(E): Client receives the code and passes it securely to the corresponding Agent.
(F): Agent requests Delegated Access Token using the `urn:ietf:params:oauth:grant-type:agent-authorization_code grant` type, presenting the code, PKCE verifier, and its Agent Token for authentication.
(G): Authorization Server validates the request (code, verifier, and agent token) and issues the Delegated Access Token.
(H): Agent accesses protected resources using the Delegated Access Token.
(I): Resource Server validates the token (e.g., via introspection or by verifying the signature and claims offline).

# Detailed Protocol Steps

## User Authorization Request

The client initiates the flow by directing the user's user-agent to the authorization server's authorization endpoint. This request is an extension of the standard Authorization Code Grant request [RFC6749, Section 4.1.1] and SHOULD include the `requested_agent` parameter.

    GET /authorize?response_type=code&
    client_id=<client_id>&
    redirect_uri=<redirect_uri>&
    scope=<scope>&
    state=<state>&
    code_challenge=<code_challenge>&
    code_challenge_method=S256&
    requested_agent=<agent_id> HTTP/1.1

### Parameters
  requested_agent: REQUIRED. The unique identifier of the agent for which the client is requesting delegated access on behalf of the user. This identifier MUST uniquely identify the agent within the system and MUST be understood by the Authorization Server.

  other parameters: The request MUST also include the standard OAuth 2.0 parameters such as `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, and PKCE parameters (`code_challenge` and `code_challenge_method`).

### Authorization Server Processing

Upon receiving the authorization request, the Authorization Server MUST perform the following steps:

  Validate the request parameters according to the OAuth 2.0 Authorization Code Grant [RFC6749, Section 4.1.1].
  
  Validate the `requested_agent`. The Authorization Server MUST verify that the provided requested_agent corresponds to a recognized agent identity and that this agent is permitted to be associated with the requesting client_id for this type of flow. The nature of this verification is outside the scope of this document but might involve checking an internal registry of agents or a relationship defined between clients and agents.

  Display a consent screen to the User. This screen MUST clearly indicate:
    The name or identity of the client application initiating the request.
    The identity of the agent (requested_agent) for which delegation is being requested.
    The specific scopes of access being requested.
  
  Record the user's consent decision, explicitly linking the consent to the User, the Client, and the requested_agent.

If the request is valid and the user grants consent, the Authorization Server proceeds to issue an Agent-Authorization Code. If the request is invalid or the user denies consent, the Authorization Server returns an Error Response (see Section 6.2.2).

### Agent-Authorization Code Response

If the user grants consent, the Authorization Server issues an Agent-Authorization Code and redirects the user-agent back to the client's redirect_uri (if provided in the request) or a pre-registered redirect URI.

  HTTP/1.1 302 Found
  Location: <redirect_uri>?code=<agent_authorization_code>&state=<state>

### Parameters
  Similar to the standard Authorization Code Grant [RFC6749, Section 4.1.2], the response includes:

  code: REQUIRED. The Agent-Authorization Code issued by the Authorization Server. This code is a short-lived, single-use code that the client will pass to the agent.
  state: OPTIONAL. The state parameter passed in the initial request, if present. This value MUST be included in the redirect URI to maintain state between the request and callback.

### Error Response

If the request fails or the user denies consent, the Authorization Server redirects the user-agent back to the client's redirect_uri with error parameters.

HTTP/1.1 302 Found
Location: <redirect_uri>?error=<error_code>&state=<state>

## Delegated Access Token Request

Upon receiving the Agent-Authorization Code, the client then requests a Delegated Access Token from the Authorization Server's token endpoint using the custom `urn:ietf:params:oauth:grant-type:agent-authorization_code` grant type.

  POST /token HTTP/1.1
  Host: authorization-server.com
  Content-Type: application/x-www-form-urlencoded

  grant_type=urn:ietf:params:oauth:grant-type:agent-authorization_code&
  client_id=<client_id>&
  code=<agent_authorization_code>&
  code_verifier=<code_verifier>&
  redirect_uri=<redirect_uri>
  agent_token=<agent_token>

### Parameters

  agent_token: REQUIRED. The agent token used to authenticate the agent. This token MUST be a valid token issued to the agent and MUST include the sub claim identifying the agent.
  other parameters: The request MUST also include the standard OAuth 2.0 parameters such as `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, and PKCE parameters (`code_challenge` and `code_challenge_method`).

### Authorization Server Processing
Upon receiving the token request, the Authorization Server MUST perform the following steps:

  Validate the request parameters according to the OAuth 2.0 Token Endpoint [RFC6749, Section 4.1.3].
  
  Verify that the authenticated agent identity (obtained from the Agent Token's sub claim) matches the requested_agent value that the user consented to during the initial Authorization Request and which is associated with the code. This step links the agent's authentication to the user's consent for that specific agent.

If all validations pass, the Authorization Server issues a Delegated Access Token. If any validation fails, the Authorization Server returns an Error Response (see Section 6.4.2).

### Delegated Access Token Response

If the Token Request is valid, the Authorization Server issues a Delegated Access Token to the agent. This token SHOULD be a JSON Web Token (JWT) [RFC7519] to include claims that document the delegation.

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

### Parameters
  Similar to the standard Authorization Code Grant [RFC6749, Section 4.1.2]

### Error Response

If the request is invalid, the Authorization Server returns an error response with an HTTP 400 (Bad Request) status code.

  HTTP/1.1 400 Bad Request
  Content-Type: application/json;charset=UTF-8
  Cache-Control: no-store
  Pragma: no-cache

  {
    "error": "invalid_grant"
  }

# Delegated Access Token Structure and Claims

The Delegated Access Token SHOULD be a JWT [RFC7519] to carry claims that explicitly document the delegation chain. Resource Servers MUST validate the token's signature and expiration.

In addition to standard JWT claims (e.g., iss, aud, exp, iat, jti), a Delegated Access Token issued via this flow MUST contain the following claims:

  sub: REQUIRED. Identifies the User (resource owner) on whose behalf the agent is acting. The value of the sub claim is a unique identifier for the user at the issuer.
  azp: REQUIRED. Authorized party - the client application that initiated the authorization request [RFC8693, Section 4.2]. This claim identifies the client ID of the application that facilitated the user's consent and provided the code to the agent.
  act: REQUIRED. Actor - represents the party acting on behalf of the subject [RFC8693, Section 4.1]. In a Delegated Access Token issued via this flow, this claim MUST contain a JSON object with at least the following member:
    sub: REQUIRED. The unique identifier of the Agent that is acting on behalf of the user. The value of this claim MUST match the agent identity authenticated by the Agent Token during the Token Request and the requested_agent value from the Authorization Request.
    Additional members MAY be included in the act claim (e.g., iss if the agent token was issued by a different party, or custom agent attributes).

  An aut (Authentication Context Class Reference) claim MAY be included to provide information about the authentication context. While not strictly required by [RFC8693], if used in this context:

  aut: OPTIONAL. A set of strings that specifies the authentication context class reference values. If used, it could potentially indicate the type of entity represented by the sub and act claims. 

  Example Decoded JWT Payload:

  {
  "iss": "https://authorization-server.com/oauth2/token",
  "aud": "resource_server",
  "sub": "user-456",
  "azp": "s6BhdRkqt3",
  "scope": "read:email write:calendar",
  "exp": 1746009896,
  "iat": 1746006296,
  "jti": "unique-token-id",
  "act": {
    "sub": "agent-finance-v1",
    "aut": "APPLICATION_AGENT" // Example usage
  },
  "aut": "APPLICATION_USER" // Example usage for the 'sub' (user)
}

Resource Servers consuming this token can inspect the sub claim to identify the user, the azp claim to identify the client application, and the act.sub claim to identify the specific agent that is performing the action. This provides a clear and auditable delegation path.

# Security Considerations

Agent Authentication: The security of this flow relies heavily on the Authorization Server's ability to securely authenticate the agent during the Token Request using the Agent Token. The method by which agents obtain and secure their Agent Tokens is critical and outside the scope of this specification but MUST be implemented securely.

Proof Key for Code Exchange (PKCE): PKCE [RFC7636] is REQUIRED to prevent authorization code interception attacks, especially relevant if the client (and thus the agent receiving the code) is a public client or runs in an environment where the redirect URI cannot be strictly protected.

Single-Use and Short-Lived Agent-Authorization Codes: Agent-Authorization Codes MUST be single-use and have a short expiration time to minimize the window for compromise.

Binding Code to Agent and Client: The Authorization Server MUST bind the Agent-Authorization Code to the specific user, client (client_id), and requested agent (requested_agent) during issuance and verify this binding during the Token Request.

Clear User Consent: The consent screen presented to the user MUST clearly identify the agent and the requested scopes to ensure the user understands exactly what authority they are delegating and to whom.

Auditability: The claims in the Delegated Access Token (sub, azp, act) provide essential information for auditing actions performed using the token, clearly showing who (user) authorized the action, which application (client) facilitated it, and which entity (agent) performed it.

Token Revocation: Mechanisms for revoking Delegated Access Tokens are essential. Revocation could be triggered by:
  The user revoking consent.
  The agent's Agent Token being revoked.
  The user's account being disabled.
  The agent's identity being disabled.
  The client application being disabled. Resource Servers or Authorization Servers MUST have mechanisms to check the revocation status of tokens (e.g., via introspection [RFC7662]).


--- back
