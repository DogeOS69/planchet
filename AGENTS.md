# Public API design

For new and evolving public APIs, first reference Alloy's corresponding crate
boundaries, provider methods, and request/response APIs, then adapt them to the
Dogecoin protocol. Design general-purpose APIs, with DogeOS as one consumer.

# Pull requests

Use a scoped title for every pull request, in the form `type(scope): summary`.
Choose a scope that names the affected component, such as
`feat(guest): accelerate OpenVM hashing and ECDSA verification`.
