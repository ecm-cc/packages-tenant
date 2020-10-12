/* eslint-disable max-len */
const crypto = require('crypto');

module.exports = tenant;

const systemBaseUriHeader = 'x-dv-baseuri';
const tenantIdHeader = 'x-dv-tenant-id';
const signatureHeader = 'x-dv-sig-1';

function tenant(defaultSystemBaseUri, base64SignatureSecret) {
    // eslint-disable-next-line no-shadow
    return function tenant(req, res, next) {
        const systemBaseUri = req.get(systemBaseUriHeader);
        const tenantId = req.get(tenantIdHeader);
        const base64Signature = req.get(signatureHeader);

        if (systemBaseUri || tenantId) {
            if (!base64SignatureSecret) {
                const err = new Error(`error validating signature for headers '${systemBaseUriHeader}' and '${tenantIdHeader}' because secret SIGNATURE_SECRET has not been configured`);
                err.status = 500;
                throw err;
            }
            if (!base64Signature) {
                const err = new Error(`error validating signature for headers '${systemBaseUriHeader}' and '${tenantIdHeader}' because signature header '${signatureHeader}' is missing.`);
                // Forbidden
                err.status = 403;
                throw err;
            }
            const binarySignatureSecret = Buffer.from(base64SignatureSecret, 'base64');
            const computedHmac = crypto.createHmac('sha256', binarySignatureSecret).update(systemBaseUri + tenantId);
            const isValid = crypto.timingSafeEqual(Buffer.from(base64Signature), Buffer.from(computedHmac.digest('base64')));

            if (!isValid) {
                const err = new Error(`error signature '${base64Signature}' is not valid for SystemBaseUri '${systemBaseUri}' and TenantId '${tenantId}'`);
                // Forbidden
                err.status = 403;
                throw err;
            }
        }
        // tenant 0 is reserved for environments which don't support multitenancy and
        // therefore can not transmit tenant headers. So there is only one tenant "0".
        // As soon as this environment supports additonal tenants these additional tenants will
        // have an id != "0"
        req.tenantId = tenantId || 0;
        req.systemBaseUri = systemBaseUri || defaultSystemBaseUri;
        next();
    };
}
