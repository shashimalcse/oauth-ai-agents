---
title: "OAuth 2.0 Extension: Authorization for AI Agents"
abbrev: "OAuth 2.0 Extension: Authorization for AI Agents"
category: info

docname: draft-oauth-ai-agents-02
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
 - actor
 - obo
 - oauth
 - agent-identity

author:
 -
    fullname: Thilina Shashimal Senarath
    organization: WSO2
    email: thilinasenarath97@gmail.com
 -  
    fullname: Ayesha Dissanayaka
    organization: WSO2
    email: ayshsandu@gmail.com
 -
    fullname: Adrian Frei
    organization: Microsoft
    email: adfrei@microsoft.com
 -  
    fullname: Brandon Werner
    organization: Microsoft
    email: Brandon.Werner@microsoft.com
 -
    fullname: Diana Smetters
    organization: Microsoft
    email: diana.smetters@microsoft.com
 -  
    fullname: Sreyantha Chary Mora
    organization: Microsoft
    email: sreyanthmora@microsoft.com

normative:
  RFC2119:
  RFC6749:
  RFC7519:
  RFC7591:
  RFC7592:
  RFC7636:
  RFC7800:
  RFC8174:
  RFC8693:
  RFC9068:
  RFC9396:

--- abstract

This document outlines how AI agents can use OAuth 2.0 for secure authentication and authorization when acting autonomously or on behalf of others, building on existing OAuth 2.0 features with attention to security and clear delegation in AI workflows. This draft proposes new claims to describe the subject and actor/client.

--- middle

# Introduction

AI agents are increasingly used to perform tasks for humans or systems, often needing secure access to protected resources. This document discusses applying OAuth 2.0 to AI agents, focusing on security, precise delegation, and traceability. No new grant types or protocols are introduced; instead, existing OAuth 2.0 flows such as the Authorization Code Grant (see {{RFC6749|Section 4.1}}), the Client Credentials Grant (see {{RFC6749|Section 4.4}}), and Token Exchange {{RFC8693}} are adapted for AI agent scenarios.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

## Terminology

The terms "User", "Client", "Authorization Server", "Resource Server", and "Access Token" are defined in {{RFC6749|Section 1.1}}. This document also uses the following terms:

Agent Application: : Software that performs agent tasks; it can be standalone, web-based, or a service acting for users or systems.

Agent: : A registered OAuth client accessing protected resources for another entity, often as an automated system or application; usually linked to an agent application.

Agent Identity: : A unique identifier distinguishing each Agent Application and Agent from others. This can be used as the subject identity in tokens for that agent.

# Motivation

AI agents are now used for complex tasks in many settings, including personal assistants and autonomous business applications. To operate effectively, these agents often need access to protected resources like APIs or user data. While OAuth 2.0 offers a strong authorization framework, it must be tailored to fit the specific needs of AI agents to ensure the Agent’s actions are secure and traceable.

## Scenarios

Autonomous AI Agents:
: Operate independently without human input, like self-driving car controllers or automated network managers. These don’t operate within a user context (even though they may be associated with human owners or sponsors but aren’t acting on their behalf).

Delegated Action on Behalf of Users:
: Work within user-directed workflows, completing tasks as an extension of the user, such as scheduling assistants or information retrievers. These operate within a user context.

Delegated Action Between Agents:
: One agent delegates tasks to another, for instance, a booking assistant handing off flight arrangements to a specialized travel API agent.

# OAuth2.0 for AI Agents

In this framework, AI agents authenticate as OAuth clients and interact with OAuth authorization servers via the typical flows (Authorization Code Flow, Client Credentials Flow, and Token Exchange Flow). The agent will be treated like any other OAuth client.

The key difference is that the agent's identity and the context in which it operates will be more complex, requiring additional claims and metadata to accurately represent the agent's role and permissions.

## Dynamic Client Registration

OAuth 2.0 Dynamic Client Registration extension ({{RFC7591}}) allows clients, including AI agents, to register with an Authorization Server dynamically. For agents to obtain client credentials and access tokens, the Authorization Server MUST support this protocol. Authorization Servers MAY limit dynamic registration to certain agent publishers or scenarios, and MUST associate a unique Agent Identity with each registered agent for identification during authorization.

Authorization Servers MAY set additional requirements for agent registration (e.g., scopes, metadata, user consent) to meet security and privacy needs. They SHOULD differentiate between agents and standard OAuth clients to apply suitable policies. The DCR endpoint MAY require extra parameters to specify agent type and delegation semantics, informing appropriate security models and authorization scopes.

Extending DCR and evaluating additional options for Agent registration, such as SPIFFE, are not addressed in this draft. For the purposes of this document, it is assumed that the Authorization Server supports dynamic Agent registration following a standard method, and that Agents have the capability to discover registration procedures and register themselves when required to perform an action.

## Agent Identity

The Agent Identity uniquely identifies an agent in a system, usually as a URI or unique string linked to its credentials. Agent Identity is essential in OAuth 2.0 for secure delegation, traceability, and identity management for AI agents.

It is used for:

* Including in access tokens issued to the agents
* Signaling the acting agent in authorization requests
* Tracking and attributing actions in audit logs
* Representing the agent in delegation chains
* Keeping track of user consent and granted permissions for specific agents
* Enable creation of policies to govern the specific agent
* Track the specific agent actor, even when acting on behalf of users or other agents

# Access Token Structure and Claims

Access tokens issued to Agents SHOULD use the JWT Profile for OAuth 2.0 Access Tokens {{RFC9068}}. They SHOULD carry claims that convey identity and explicitly document the delegation.

Authorization Servers MUST include the following claims in the access tokens issued to Agents:

sub (Subject):
: REQUIRED. Identifies the User or entity on whose behalf the Agent acts. An Agent MAY be its own subject if it is acting autonomously (even if created or associated with a human User as the Agent’s owner or sponsor).

aud (Audience):
: REQUIRED. Specifies the Resource Server that will validate the token.

scope (Scope):
: OPTIONAL. A space-separated list of OAuth scopes granted to the Agent.

authorization_details:
: OPTIONAL. A JSON object specifying permissions granted to the Agent, following the structure defined in Rich Authorization Requests {{RFC9396}}.

Either scope or authorization_details MUST be included in the token to specify the Agent’s permissions.

client_id:
: REQUIRED. Indicates the OAuth Client to whom the token was issued. This also is the Agent ID and represents the actor performing the action.

sub_entity_type (Subject Entity Type):
: REQUIRED. Specifies the type of entity represented by the sub (Subject) claim. Its value MUST be one of "user" (indicating a human end-user), "agent" (indicating an autonomous or delegated AI agent or automated system), or "app" (indicating a standard OAuth client application not acting as an agent).

client_entity_type (Client Entity Type):
: REQUIRED. Indicates the type of entity represented by the client_id claim. Its value MUST be either "agent" (for AI or automated agent clients) or "app" (for standard OAuth client applications not acting as an agent).

sub_parent (Subject Parent App):
: RECOMMENDED. Identifies the subject's Agent Application when the subject (sub) is an Agent. This claim SHOULD be present only if the value of the sub_entity_type claim is "agent". In all other cases, the sub_parent claim MUST NOT be included.

client_parent (Client Parent App):
: RECOMMENDED. Identifies the Agent Application of the Agent identified by the client_id claim. The client_parent claim SHOULD be present only if the client_entity_type claim has the value "agent". Otherwise, this claim MUST NOT be included.

The sub_parent and client_parent claims are used to represent the owning or parent application of the subject (sub) and client (client_id), respectively. These claims help link an agent instance to the broader application or deployment it belongs to, supporting policy decisions and traceability. They SHOULD be included when the subject or client is an agent instance to enable clear relationships between agents and their controlling applications.

Authorization Servers MAY include the act (Actor) claim to explicitly represent delegation chains. To control token size and ensure predictable processing time at Resource Servers, Authorization Servers MAY limit the depth of nested act structures.

act (Actor):
: RECOMMENDED. Identifies the Agent currently performing the action (typically the same as the client_id). This claim is used to represent delegation chains where Agents act on behalf of others using Token Exchange ({{RFC8693}}).

Authorization Servers SHOULD impose practical limits on the nesting depth of the act claim to prevent token size bloat and ensure efficient validation by Resource Servers. While no fixed limit is mandated, a typical recommendation is to restrict the chain to 3–5 delegation levels, balancing expressiveness and performance.

## Example decoded JWT payload

~~~
{ 
  "sub": "user-id-123", 
  "sub_entity_type": "user", 
  "aud": "https://api.example.com", 
  "scope": "read:email write:calendar", 
  "client_id": "agent-xyz-instance-id-456", 
  "client_entity_type": "agent", 
  "client_parent": "agent-xyz-app-789", 
  "act": { 
    "sub": "agent-xyz-instance-id-456", 
    "sub_entity_type": "agent", 
    "sub_parent": "agent-xyz-app-789", 
    "act": { 
      "sub": "agent-abc-instance-id-123", 
      "sub_entity_type": "agent", 
      "sub_parent": "agent-abc-app-1610" 
    } 
  } 
}
~~~

# Authorization Server Behavior  

Authorization Servers MUST:

* Verify the Agent’s identity and permissions prior to issuing access tokens.
* Confirm that the Agent is registered and authorized to act on behalf of the User or another Agent.
* Include all required claims as specified in Section 4.
* Provide mechanisms for users to review, manage, and revoke Agent access and consent.

It is RECOMMENDED that Authorization Servers log all Agent-related actions and access events to support auditing and accountability.

Authorization Servers MAY implement additional security controls such as rate limiting, IP allowlisting, or other measures to mitigate the risk of Agent misuse.

## User Consent Experience

Authorization Servers SHOULD clearly communicate to end-users the identity of the acting agent, the permissions requested, and the implications of consent (where applicable) during authorization prompts. Consent screens should be designed to be understandable, minimizing ambiguity about which agent is requesting access and what actions it may perform on the user’s behalf.

# Resource Server Behavior

Resource Servers MUST validate access tokens and their claims prior to granting access to protected resources. They SHOULD log all access attempts to support auditing and security.

Specifically, Resource Servers MUST:

* Validate that the access token is issued by a trusted Authorization Server and remains valid.
* Verify that the token scopes authorize the requested resource access.

If the access token is missing, invalid, or insufficient for the requested operation, the Resource Server MUST respond with an appropriate error, typically one of: HTTP 400 (Bad Request), HTTP 401 (Unauthorized), or HTTP 403 (Forbidden), and include a WWW-Authenticate header describing the error.

It is RECOMMENDED that Resource Servers:

* Log relevant token claims and request details to ensure traceability and auditability.
* Use entity-describing claims (e.g., client_entity_type, sub_entity_type, client_parent, sub_parent) to make authorization decisions regarding Agent actions.

Resource Servers MAY apply additional protections such as rate limiting or IP allowlisting to reduce abuse risks from agents.

# Incremental Authorization

Incremental authorization enables Agents to request only the permissions required for a specific task, deferring the acquisition of additional scopes until they are needed. This strategy reduces the risk of over-privileged access and aligns access token scopes with real-time operational context.

Agents can dynamically determine the necessary permissions by relying on [Protected Resource Metadata] as defined in OAuth 2.0 Protected Resource Metadata {{RFC8414}} and responding to WWW-Authenticate challenges issued by Resource Servers. When a token is insufficient—due to missing scopes or delegation context—the Resource Server challenges the Agent (e.g., error="insufficient_scope"), prompting a subsequent authorization request to acquire the necessary access.

Where supported, Authorization Servers MAY employ a CIBA-style (Client-Initiated Backchannel Authentication) authorization flow to facilitate end-user consent. This is particularly useful in non-interactive or delegated scenarios involving AI agents.

# Security Considerations

Token Integrity and Transport Security:
: Access Tokens issued to Agents MUST be transmitted securely using HTTPS, as per {{RFC6749}}, to protect against token interception. Tokens MUST be cryptographically signed (e.g., as JWTs per {{RFC9068}}) and validated by Resource Servers to ensure their integrity and authenticity.

Scope Minimization and Principle of Least Privilege:
: The scopes or authorization_details {{RFC9396}} granted to Agents MUST be restricted to the minimum required for the Agent’s intended functionality. This mitigates the impact of token leakage or Agent compromise.

Token Revocation and Expiration:
: Access Tokens MUST have bounded lifetimes, and Authorization Servers MUST offer mechanisms to revoke tokens (e.g., via token revocation endpoint as per {{RFC7009}}). This is especially useful when an Agent is suspected to be compromised or misbehaving.

Token Binding and Replay Protection:
: To mitigate replay attacks and unauthorized token use, Authorization Servers and Clients SHOULD implement token binding mechanisms, such as those described in {{RFC7800}} (OAuth 2.0 Token Binding). Binding tokens cryptographically to the client or agent instance ensures tokens cannot be reused by malicious actors. Resource Servers SHOULD validate token bindings where supported.

Delegation Risks:
: Authorization Servers and Resource Servers SHOULD validate delegation, ensuring that agents only act within the bounds of their delegated authority. This includes validating the act claim and ensuring that the agent has the necessary permissions to perform the requested actions on behalf of the user or another agent.

PKCE Enforcement for Public Clients:
: All Agents registered as Public Clients MUST use Proof Key for Code Exchange (PKCE) {{RFC7636}} to protect against code interception. Confidential Clients SHOULD use PKCE when redirect URIs cannot be strongly protected, such as in native or embedded environments.

User Consent Clarity and Management:
: The Authorization Server SHOULD clearly indicate the identity of the acting Agent and the requested permissions (scopes or authorization_details) during consent prompts. It MUST provide end-users with management interfaces to view, audit, and revoke consent previously granted to Agents.

Auditability and Accountability:
: The claims in the access token provide essential information for auditing actions performed using the token, clearly showing who (sub) authorized the action, which application (client) facilitated it and performed the action. Resource servers MUST log access requests made by agents, including the Agent identity, subject, entity-describing information, and actions performed. These logs enable traceability of who authorized what action, by which Agent, and on whose behalf. Logging MUST follow applicable privacy and compliance guidelines.

# IANA Considerations  

This document requests registration of the following claims in the JSON Web Token (JWT) Claims registry, established by {{RFC7519}}, in the "JSON Web Token Claims" registry located at https://www.iana.org/assignments/jwt:

* Claim Name: "sub_entity_type"
* Claim Description: Identifies the type of subject entity (e.g., "user", "agent", "app").
* Change Controller: IESG
* Specification Document(s): Section 4 of this document

* Claim Name: "client_entity_type"
* Claim Description: Identifies the type of client entity (e.g., "agent", "app").
* Change Controller: IESG
* Specification Document(s): Section 4 of this document

* Claim Name: "sub_parent"
* Claim Description: Identifies the parent entity of the subject, if applicable.
* Change Controller: IESG
* Specification Document(s): Section 4 of this document

* Claim Name: "client_parent"
* Claim Description: Identifies the parent application or entity responsible for the client.
* Change Controller: IESG
* Specification Document(s): Section 4 of this document

Note: These claims are intended to support agent identity, delegation semantics, and traceability in OAuth 2.0-based authorization scenarios involving AI agents and other autonomous clients. Claims are OPTIONAL unless explicitly required by the Authorization Server.

--- back

# Appendix A. Example Access Tokens for Agent Scenarios

This appendix provides example access tokens issued to AI agents under three different usage scenarios. Each example demonstrates how claims such as "sub", "client_id", and delegation-related claims are structured to reflect the relationship between the agent, its parent, and any subject it represents.

These examples are illustrative and omit optional claims such as exp, iat, iss, and jti for brevity.

## A.1. Autonomous AI Agents

In this scenario, an autonomous AI agent acts independently without any user or delegator. The agent obtains a token via the Client Credentials Grant. The token includes claims identifying the agent as both the subject (sub) and the client (client_id), along with its parent application.

~~~
{ 
  "sub": "agent-xyz-instance-id-456", 
  "sub_entity_type": "agent", 
  "sub_parent": "agent-xyz-app-789", 
  "aud": "https://api.example.com", 
  "scope": "read:email write:calendar", 
  "client_id": "agent-xyz-instance-id-456", 
  "client_entity_type": "agent", 
  "client_parent": "agent-xyz-app-789" 
} 
~~~

## A.2. Delegated Action on Behalf of Users

In this scenario, an agent performs actions on behalf of a user. It obtains a token using the Authorization Code Grant. The token reflects the user as the subject (sub) and the agent as the client (client_id).

~~~
{ 
  "sub": "user-id-123", 
  "sub_entity_type": "user", 
  "aud": "https://api.example.com", 
  "scope": "read:email write:calendar", 
  "client_id": "agent-xyz-instance-id-123", 
  "client_entity_type": "agent", 
  "client_parent": "agent-xyz-app-1610" 
} 
~~~

## A.3. Delegated Action Between Agents

This example illustrates a scenario where one agent delegates a task to another agent using the OAuth 2.0 Token Exchange. The client_id claim indicates the current actor. The act claim is used to encode a delegation chain. The top-level sub represents the user on whose behalf the action is ultimately being taken.

~~~
{ 
  "sub": "user-id-123", 
  "sub_entity_type": "user", 
  "aud": "https://api.example.com", 
  "scope": "read:email write:calendar", 
  "client_id": "agent-xyz-instance-id-456", 
  "client_entity_type": "agent", 
  "client_parent": "agent-xyz-app-789", 
  "act": { 
    "sub": "agent-xyz-instance-id-456", 
    "sub_entity_type": "agent", 
    "sub_parent": "agent-xyz-app-789", 
    "act": { 
      "sub": "agent-abc-instance-id-123", 
      "sub_entity_type": "agent", 
      "sub_parent": "agent-abc-app-1610" 
    } 
  } 
}
~~~
