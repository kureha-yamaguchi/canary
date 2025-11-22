SYSTEM_PROMPT = """
You are coming up with a plausible scenario for an exploitation an attack on a public website.

You have the freedom to choose the type of website and vulnerability you want to exploit so that it best fits the technique you're given. 

You'll also be provided with a list of other techniques that you can choose to use in your attack if you want to.

You should think about this step by step:

1. What is a way that you might use this technique in practice?
2. Think about what a website might look like for this?
3. Think about what the vulnerability might be?
4. Think about what the other techniques might be that you could use to help you exploit this. It ranges a lot. Sometimes it's just one. Sometimes it's up to 20.
5. Once you have the story then generate the list of techniques that are used in order to exploit this.
"""

USER_PROMPT = """
Please now generate a realistic scenario and the steps you took to exploit it on the website for the following technique:

<required_technique>
{required_technique}
</required_technique>

<possible_techniques>
{possible_techniques}
</possible_techniques>

You should only choose vulnerability types from the following list:
- jwt-secret-exposed
- jwt-algorithm-confusion
- oauth-state-parameter-missing
- oauth-redirect-uri-not-validated
- password-reset-token-predictable
- session-fixation-vulnerable
- authentication-bypass-via-http-verb
- insecure-direct-object-reference
- broken-function-level-authorization
- mass-assignment-vulnerability
- privilege-escalation-via-parameter-pollution
- horizontal-privilege-escalation
- vertical-privilege-escalation
- missing-re-authentication-sensitive-actions
- account-takeover-via-email-verification
- subdomain-takeover-sso
- graphql-introspection-enabled
- graphql-batch-query-abuse
- graphql-depth-limit-missing
- rest-api-no-rate-limiting
- rest-api-verbose-errors
- api-version-disclosure
- api-key-in-url-parameters
- api-key-in-client-code
- cors-misconfiguration-credentials
- jsonp-callback-injection
- xml-external-entity-injection
- server-side-request-forgery
- api-pagination-manipulation
- websocket-origin-not-validated
- session-token-in-url
- session-not-invalidated-logout
- concurrent-session-not-prevented
- session-timeout-excessive
- cookie-without-secure-flag
- cookie-without-httponly-flag
- cookie-without-samesite-attribute
- csrf-token-missing
- csrf-token-not-validated
- csrf-token-predictable
- sensitive-data-in-git-history
- environment-variables-exposed
- source-maps-in-production
- debug-endpoints-enabled
- admin-panel-publicly-accessible
- graphql-field-suggestions-leak-schema
- timing-attack-user-enumeration
- cache-poisoning-sensitive-data
- http-response-splitting
- information-disclosure-via-errors
- directory-listing-enabled
- backup-files-accessible
- unreferenced-files-accessible
- metadata-leakage-documents
- s3-bucket-public-read
- s3-bucket-public-write
- s3-bucket-authenticated-users-access
- cloud-storage-predictable-urls
- cloud-function-unauthenticated-invoke
- iam-role-overly-permissive
- security-group-too-broad
- cloud-database-publicly-accessible
- kubernetes-dashboard-exposed
- docker-api-unauthenticated
- container-running-as-root
- secrets-in-container-environment-vars
- cloud-metadata-service-accessible
- subdomain-takeover-dangling-cname
- sql-injection-union-based
- sql-injection-blind-boolean
- sql-injection-time-based
- nosql-injection-mongodb
- command-injection-os
- ldap-injection
- xpath-injection
- template-injection-server-side
- template-injection-client-side
- log-injection-crlf
- header-injection
- host-header-injection
- regex-denial-of-service
- race-condition-coupon-redemption
- race-condition-fund-transfer
- price-manipulation-client-side
- quantity-limit-bypass
- referral-bonus-self-referral
- discount-code-reuse
- workflow-bypass-direct-url
- payment-amount-tampering
- checkout-process-manipulation
- inventory-limit-bypass
- subscription-downgrade-bypass
- trial-period-reset
- captcha-reuse
- captcha-client-side-only
- unrestricted-file-upload
- file-upload-content-type-not-validated
- file-upload-double-extension-bypass
- file-upload-path-traversal
- file-upload-stored-xss
- file-upload-xxe-via-svg
- zip-slip-vulnerability
- image-tragick-vulnerability
- pdf-upload-javascript-execution
- unrestricted-file-download
- path-traversal-file-download
- weak-password-hashing
- hardcoded-encryption-key
- weak-random-number-generator
- predictable-reset-tokens
- insecure-randomness-session-ids
- encryption-key-in-client-code
- tls-certificate-not-validated
- mixed-content-https-page
- downgrade-attack-vulnerable
- outdated-javascript-library
- vulnerable-npm-dependency
- subresource-integrity-missing
- cdn-compromise-vulnerable
- third-party-script-unvalidated
- npm-package-typosquatting-risk
- dependency-confusion-vulnerable
- prototype-pollution-lodash
- application-layer-dos-large-payload
- xml-bomb-vulnerability
- regular-expression-dos
- algorithmic-complexity-dos
- resource-exhaustion-file-upload
- slowloris-vulnerable
- zip-bomb-processing
- web3-reentrancy-attack
- smart-contract-integer-overflow
- oauth-account-hijacking-via-redirect
- saml-assertion-not-validated
- jwt-none-algorithm-accepted
- insecure-deserialization
- prototype-pollution-client-side
- cache-deception-attack
- http-request-smuggling
- http-response-splitting
- host-header-authentication-bypass
- websocket-hijacking
- postmessage-origin-not-validated
- dom-based-xss
- reflected-xss
- stored-xss
- blind-xss
- mutation-xss
- dangling-markup-injection
- default-credentials-not-changed
- swagger-ui-exposed-production
- actuator-endpoints-unsecured
- prometheus-metrics-exposed
- kibana-dashboard-unauthenticated
- redis-unauthenticated-access
- mongodb-no-authentication
- elasticsearch-open-access
- memcached-exposed-udp
- jenkins-unauthenticated-access
- git-directory-exposed
- svn-directory-exposed
- phpinfo-exposed
- server-status-page-enabled
- trace-method-enabled

Please now generate a realistic scenario and the steps you took to exploit it on the website.
"""
