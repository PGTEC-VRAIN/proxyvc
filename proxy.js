const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { SignJWT, importPKCS8 } = require('jose');
const fs = require('fs');

const app = express();
const PORT = 8090;

// =============================================================
// Proxy target
// =============================================================
const APISIX_URL = process.env.APISIX_URL || "https://apisix-avamet-ds.pgtec-vrain-dataspace.eu";

// =============================================================
// VC Issuance config  (replicates get_credential.sh)
// =============================================================
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "https://keycloak-iiama.pgtec-vrain-dataspace.eu";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "provider";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || "account-console";
const KEYCLOAK_USERNAME = process.env.KEYCLOAK_USERNAME || "provider";
const KEYCLOAK_PASSWORD = process.env.KEYCLOAK_PASSWORD || "test";
const CRED_CONFIG_ID = process.env.CRED_CONFIG_ID || "machine-sd";
const CRED_FORMAT = process.env.CRED_FORMAT || "vc+sd-jwt";

// =============================================================
// Refresh intervals
// =============================================================
const VC_REFRESH_INTERVAL = 24 * 60 * 60_000; // 24 hours
const VP_REFRESH_INTERVAL = 10 * 60_000;       // 10 minutes

// =============================================================
// VP / Access Token config  (replicates get_access.sh)
// =============================================================
const VERIFIER_URL = process.env.VERIFIER_URL || "https://verifier-avamet-ds.pgtec-vrain-dataspace.eu/services/machine-id";
const VP_CLIENT_ID = process.env.VP_CLIENT_ID || "machine-id";
const VP_SCOPE = process.env.VP_SCOPE || "operator1";
const DID_FILE = process.env.DID_FILE || "./wallet-identity/did.json";
const KEY_FILE = process.env.KEY_FILE || "./wallet-identity/private-key.pem";

// =============================================================
// Wallet key material — shared by CredentialManager (proof-of-possession on
// issuance) and TokenManager (VP signing on presentation). Loaded once and
// cached, since CredentialManager.issue() now needs it before TokenManager
// ever initializes.
// =============================================================
let _walletIdentity = null;
async function getWalletIdentity() {
  if (_walletIdentity) return _walletIdentity;
  const crypto = require('crypto');
  const { importJWK } = require('jose');

  const holderDid = JSON.parse(fs.readFileSync(DID_FILE, 'utf8')).id;
  const privateKeyPem = fs.readFileSync(KEY_FILE, 'utf8');
  const keyObject = crypto.createPrivateKey(privateKeyPem);
  const jwk = keyObject.export({ format: 'jwk' });
  const { d, ...publicJwk } = jwk; // strip private material for use in proof headers
  const privateKey = await importJWK(jwk, 'ES256');

  _walletIdentity = { holderDid, privateKey, publicJwk };
  return _walletIdentity;
}

// =============================================================
// Credential Manager — issues a fresh VC from Keycloak
// =============================================================
class CredentialManager {
  constructor() {
    this.vcJwt = null;
    this.refreshTimer = null;
  }

  /**
   * Full OID4VCI flow: login → offer → pre-auth code → VC
   */
  async issue() {
    const base = KEYCLOAK_URL.replace(/\/$/, '');
    const tokenUrl = `${base}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;

    // 1. Login to Keycloak
    console.log('[VC] Logging in as', KEYCLOAK_USERNAME);
    const loginRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: KEYCLOAK_CLIENT_ID,
        username: KEYCLOAK_USERNAME,
        password: KEYCLOAK_PASSWORD,
        scope: 'openid',
      }),
    });
    const loginData = await loginRes.json();
    if (!loginData.access_token) throw new Error(`Keycloak login failed: ${JSON.stringify(loginData)}`);
    const accessToken = loginData.access_token;

    // 2. Get credential offer URI
    // Note: the real Keycloak REST resource is "create-credential-offer", not
    // "credential-offer-uri" (that path 404s). pre_authorized=true is required
    // so the offer carries a pre-authorized_code grant, matching step 3 below —
    // without it the offer uses the interactive authorization_code grant instead.
    console.log('[VC] Fetching credential offer URI');
    const offerRes = await fetch(
      `${base}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/create-credential-offer?credential_configuration_id=${CRED_CONFIG_ID}&pre_authorized=true`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const offerData = await offerRes.json();
    if (!offerRes.ok) throw new Error(`Credential offer creation failed: ${JSON.stringify(offerData)}`);
    // offerData.nonce has no leading slash — the real endpoint is
    // {issuer}/{nonce}, and bare concatenation silently 404s.
    const offerUrl = `${offerData.issuer}/${offerData.nonce}`;

    // 3. Get pre-authorized code
    console.log('[VC] Requesting pre-authorized code');
    const preAuthRes = await fetch(offerUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const preAuthData = await preAuthRes.json();
    const preAuthCode = preAuthData.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'];
    if (!preAuthCode) throw new Error(`No pre-authorized_code in offer: ${JSON.stringify(preAuthData)}`);

    // 4. Exchange pre-auth code for credential access token
    console.log('[VC] Exchanging code for credential access token');
    const credTokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode,
      }),
    });
    const credTokenData = await credTokenRes.json();
    if (!credTokenData.access_token) throw new Error(`Credential token exchange failed: ${JSON.stringify(credTokenData)}`);

    // The access token's authorization_details carries the *actual*
    // per-issuance credential_identifier (e.g. "ServiceCredential_0000"),
    // which differs from the credential_configuration_id used earlier —
    // sending CRED_CONFIG_ID here gets rejected as unknown_credential_identifier.
    const credIdentifier =
      credTokenData.authorization_details?.[0]?.credential_identifiers?.[0] || CRED_CONFIG_ID;

    // 5. Get a c_nonce and build a signed proof-of-possession JWT
    // (required whenever the credential config has cryptographic_binding_methods_supported set)
    console.log('[VC] Requesting c_nonce for proof of possession');
    const nonceRes = await fetch(`${base}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/nonce`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${credTokenData.access_token}` },
    });
    const nonceData = await nonceRes.json();
    if (!nonceRes.ok || !nonceData.c_nonce) throw new Error(`Nonce request failed: ${JSON.stringify(nonceData)}`);

    const identity = await getWalletIdentity();
    // Must match Keycloak's own externally-reported issuer identity exactly
    // (OID4VCIssuerWellKnownProvider.getIssuer), which can differ from `base`
    // (KEYCLOAK_URL is the in-cluster URL used just to reach the server).
    // offerData.issuer is "<credential_issuer>/protocol/oid4vc/credential-offer",
    // so strip that known suffix to recover the canonical issuer URL.
    const credentialIssuer = offerData.issuer.replace(/\/protocol\/oid4vc\/credential-offer$/, '');
    const proofJwt = await new SignJWT({ nonce: nonceData.c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: identity.publicJwk })
      .setAudience(credentialIssuer)
      .setIssuedAt()
      .sign(identity.privateKey);

    // 6. Issue the Verifiable Credential
    console.log('[VC] Issuing credential');
    const credRes = await fetch(
      `${base}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/credential`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${credTokenData.access_token}`,
        },
        body: JSON.stringify({
          credential_identifier: credIdentifier,
          format: CRED_FORMAT,
          proofs: { jwt: [proofJwt] },
        }),
      }
    );
    const credData = await credRes.json();
    // Response wraps the issued credential(s) in a "credentials" array
    // (batch-style shape) rather than a bare top-level "credential" field.
    const issuedCredential = credData.credentials?.[0]?.credential || credData.credential;
    if (!issuedCredential) throw new Error(`Credential issuance failed: ${JSON.stringify(credData)}`);

    this.vcJwt = issuedCredential;
    console.log('[VC] Credential obtained successfully');
  }

  /**
   * Issue the first VC and start the refresh loop.
   */
  async initialize() {
    await this.issue();
    this._scheduleRefresh();
  }

  getVC() {
    return this.vcJwt;
  }

  _scheduleRefresh() {
    clearTimeout(this.refreshTimer);
    console.log(`[VC] Next renewal in ${Math.round(VC_REFRESH_INTERVAL / 1000)}s`);
    this.refreshTimer = setTimeout(async () => {
      try {
        await this.issue();
      } catch (err) {
        console.error('[VC] Renewal failed:', err.message, '— retrying in 30s');
        setTimeout(() => this._scheduleRefresh(), 30_000);
        return;
      }
      this._scheduleRefresh();
      // After a new VC, the access token must be refreshed too
      await tokenManager.refresh();
    }, VC_REFRESH_INTERVAL);
  }
}

// =============================================================
// Token Manager — exchanges VC for access token via VP
// =============================================================
class TokenManager {
  constructor() {
    this.accessToken = null;
    this.tokenEndpoint = null;
    this.holderDid = null;
    this.privateKey = null;
    this.refreshTimer = null;
  }

  async initialize() {
    // Discover token endpoint
    const res = await fetch(`${VERIFIER_URL}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
    this.tokenEndpoint = (await res.json()).token_endpoint;
    console.log(`[TOKEN] Endpoint: ${this.tokenEndpoint}`);

    // Load identity
    this.holderDid = JSON.parse(fs.readFileSync(DID_FILE, 'utf8')).id;
    
    // Read the SEC1/PKCS#1 EC Private Key
    const privateKeyPem = fs.readFileSync(KEY_FILE, 'utf8');
    const crypto = require('crypto');
    const { importJWK } = require('jose');
    
    // 1. Parse with Node's crypto module (handles BEGIN EC PRIVATE KEY)
    const keyObject = crypto.createPrivateKey(privateKeyPem);
    
    // 2. Export to JWK format
    const jwk = keyObject.export({ format: 'jwk' });
    
    // 3. Import gracefully into `jose`
    this.privateKey = await importJWK(jwk, 'ES256');
    
    console.log(`[TOKEN] Holder: ${this.holderDid}`);

    await this.refresh();
  }

  async refresh() {
    try {
      const vcJwt = credentialManager.getVC();
      if (!vcJwt) throw new Error('No VC available');

      // Sign VP JWT
      const vpJwt = await new SignJWT({
        iss: this.holderDid,
        sub: this.holderDid,
        vp: {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiablePresentation"],
          verifiableCredential: [vcJwt],
          holder: this.holderDid,
        },
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: this.holderDid })
        .sign(this.privateKey);

      // Exchange for access token
      const res = await fetch(this.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'vp_token',
          client_id: VP_CLIENT_ID,
          vp_token: vpJwt,
          scope: VP_SCOPE,
        }),
      });

      const data = await res.json();
      if (!data.access_token) throw new Error(`Token exchange failed: ${JSON.stringify(data)}`);

      this.accessToken = data.access_token;
      console.log('[TOKEN] Access token obtained');
      this._scheduleRefresh();
    } catch (err) {
      console.error('[TOKEN] Refresh failed:', err.message);
      clearTimeout(this.refreshTimer);
      this.refreshTimer = setTimeout(() => this.refresh(), 30_000);
    }
  }

  getToken() {
    return this.accessToken;
  }

  _scheduleRefresh() {
    clearTimeout(this.refreshTimer);
    console.log(`[TOKEN] Next refresh in ${Math.round(VP_REFRESH_INTERVAL / 1000)}s`);
    this.refreshTimer = setTimeout(() => this.refresh(), VP_REFRESH_INTERVAL);
  }
}

// =============================================================
// Instances
// =============================================================
const credentialManager = new CredentialManager();
const tokenManager = new TokenManager();

// =============================================================
// Proxy — forward everything with Bearer token
// =============================================================
app.get('/__health', (req, res) => res.status(200).send('OK'));

app.use('/', async (req, res) => {
  const targetHost = new URL(APISIX_URL).host;
  const targetUrl = `${APISIX_URL}${req.url}`;
  
  console.log(`[PROXY] Forwarding ${req.method} ${req.url} → ${targetUrl}`);

  const token = tokenManager.getToken();
  if (!token) {
    console.warn('[PROXY] No token available');
    return res.status(503).send('No token');
  }

  const headers = {
    'Host': targetHost,
    'Authorization': `Bearer ${token}`,
    'Accept': req.headers['accept'] || 'application/ld+json',
    'Link': req.headers['link'] || '',
  };

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method,
      headers,
    });

    console.log(`[PROXY] Upstream responded ${upstream.status}`);
    
    res.status(upstream.status);
    upstream.headers.forEach((v, k) => res.setHeader(k, v));
    
    const body = await upstream.text();
    res.send(body);
  } catch (err) {
    console.error('[PROXY] fetch error:', err.message);
    res.status(502).send('Proxy error');
  }
});

// =============================================================
// Start — VC first, then token, then listen
// =============================================================
async function start() {
  await credentialManager.initialize();
  await tokenManager.initialize();
  app.listen(PORT, () => {
    console.log(`🚀 Proxy running on http://localhost:${PORT} → ${APISIX_URL}`);
  });
}

start().catch((err) => {
  console.error('Startup failed:', err.message);
  process.exit(1);
});
 