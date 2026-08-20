#!/bin/bash
# Generate development CA and per-service certificates for mTLS
# For production, replace with certificates from your organization's CA

set -e

CERTS_DIR="${CERTS_DIR:-./certs}"
CA_SUBJECT="/C=US/ST=CA/L=SanFrancisco/O=AgenticSecurity/OU=Dev/CN=agentic-dev-ca"
DAYS_VALID=365

SERVICES=(
    "registry"
    "pdp"
    "identity"
    "broker"
    "approval"
    "telemetry"
    "killswitch"
    "demo-agent"
    "idp"
    "egress-proxy"
    "edr-sensor"
    "redis"
    "lb"
)

echo "Creating certificates directory: ${CERTS_DIR}"
mkdir -p "${CERTS_DIR}"

echo "Generating CA private key..."
openssl genrsa -out "${CERTS_DIR}/ca.key" 4096

echo "Generating CA certificate..."
openssl req -new -x509 -days ${DAYS_VALID} -key "${CERTS_DIR}/ca.key" \
    -out "${CERTS_DIR}/ca.crt" -subj "${CA_SUBJECT}"

generate_service_cert() {
    local service=$1
    echo "Generating certificate for: ${service}"
    
    openssl genrsa -out "${CERTS_DIR}/${service}.key" 2048
    
    cat > "${CERTS_DIR}/${service}.cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = CA
L = SanFrancisco
O = AgenticSecurity
OU = ${service}
CN = ${service}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${service}
DNS.2 = localhost
DNS.3 = *.agentic-net
IP.1 = 127.0.0.1
EOF

    openssl req -new -key "${CERTS_DIR}/${service}.key" \
        -out "${CERTS_DIR}/${service}.csr" \
        -config "${CERTS_DIR}/${service}.cnf"
    
    openssl x509 -req -in "${CERTS_DIR}/${service}.csr" \
        -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial -out "${CERTS_DIR}/${service}.crt" \
        -days ${DAYS_VALID} \
        -extensions req_ext -extfile "${CERTS_DIR}/${service}.cnf"
    
    rm "${CERTS_DIR}/${service}.csr" "${CERTS_DIR}/${service}.cnf"
}

for service in "${SERVICES[@]}"; do
    generate_service_cert "$service"
done

chmod 600 "${CERTS_DIR}"/*.key
chmod 644 "${CERTS_DIR}"/*.crt

echo ""
echo "Certificate generation complete!"
echo "Files created in ${CERTS_DIR}:"
ls -la "${CERTS_DIR}"
echo ""
echo "To replace with organization CA:"
echo "  1. Replace ca.crt with your org's CA certificate"
echo "  2. Generate new service certs signed by your CA"
echo "  3. Update the SAN entries as needed for your DNS"
