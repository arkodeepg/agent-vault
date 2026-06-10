# Threat Model

## Requirement

Agents must be able to use API-backed capabilities without receiving raw API keys.

## Design Answer

Agent Vault is a proxy and broker:

![Agent Vault API broker flow](assets/api-broker-flow.svg)

The agent receives the result, not the key.

## Protects Against

- key leakage in chat, logs, shell output, command args, and generated files
- subprocesses reading secrets from environment variables
- agents using reveal, export, backup, or raw run paths
- accidental auth sent to an unapproved host
- accidental auth sent to a different internal HTTP port on the same host

## Does Not Protect Against

- a compromised host
- a malicious Agent Vault implementation
- a human intentionally exporting secrets
- a bad API action that was explicitly allowed

Agent Vault protects credentials. It does not decide whether an API action is a good business decision.

## Future Rule

Any new feature must be rejected if it gives an agent a raw credential or lets an agent bypass the brokered API request layer.
