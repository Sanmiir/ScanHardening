#!/bin/bash

# --- Scan de hardening v1---
#
# Dependências: apt install curl dig sslscan nuclei
# (Rode 'nuclei -update-templates' 1x)
#

# --- CORES ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- FUNÇÕES DE CHECK ---
check_fail() { echo -e "  ${RED}[FALHA]${NC} $1"; }
check_pass() { echo -e "  ${GREEN}[OK]${NC} $1"; }
check_info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

# --- DEPENDENCY CHECK ---
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}ERRO: Ferramenta '$1' não encontrada. (apt install $1)${NC}"
        exit 1
    fi
}
check_tool "curl"; check_tool "dig"; check_tool "sslscan"; check_tool "nuclei";

# --- SETUP v2.2 ---
if [ -z "$1" ]; then
    echo "Uso: $0 www.exemplo.com (não precisa de https://)"
    exit 1
fi

START_TIME=$(date +%s)
INPUT_URL="$1"
INPUT_HOSTNAME=$(echo "$INPUT_URL" | sed -e 's,^https\?://,,g' -e 's,/.*,,g')

TARGET_URL="https://$INPUT_HOSTNAME"
HOSTNAME="$INPUT_HOSTNAME"

if [[ $HOSTNAME == www.* ]]; then
    ROOT_DOMAIN=$(echo "$HOSTNAME" | sed -e 's/^www\.//')
else
    ROOT_DOMAIN="$HOSTNAME"
fi

DNS_CMD="dig @1.1.1.1 +tcp +short"

echo -e "${YELLOW}--- Iniciando Caramelo Monitor v2.2 no alvo: $TARGET_URL ---${NC}\n"

# ==========================================================
# 1. VERIFICAÇÕES SSL/TLS (Ferramenta: sslscan)
# ==========================================================
echo "[+] Checando SSL/TLS (Ferramenta: sslscan)..."
SSL_REPORT=$(sslscan --no-failed "$HOSTNAME" 2>/dev/null)
if echo "$SSL_REPORT" | grep -q "TLSv1.0.*enabled"; then check_fail "Protocolo TLS 1.0 HABILITADO."; else check_pass "Protocolo TLS 1.0 está desabilitado."; fi
if echo "$SSL_REPORT" | grep -q "TLSv1.1.*enabled"; then check_fail "Protocolo TLS 1.1 HABILITADO."; else check_pass "Protocolo TLS 1.1 está desabilitado."; fi
if echo "$SSL_REPORT" | grep -q -E "(RC4|3DES|MD5)"; then check_fail "Ciphers Fracos (RC4, 3DES, MD5) detectados."; else check_pass "Nenhum cipher fraco óbvio detectado."; fi

# ==========================================================
# 2. VERIFICAÇÕES HTTP (Headers, Cookies, Métodos)
# ==========================================================
echo -e "\n[+] Checando Headers HTTP, Cookies e Métodos..."
HEADERS=$(curl -s -I -L -k --max-time 10 "$TARGET_URL")
if echo "$HEADERS" | grep -q -i "Strict-Transport-Security"; then check_pass "Header HSTS presente."; else check_fail "Header HSTS (Strict-Transport-Security) AUSENTE."; fi
if echo "$HEADERS" | grep -q -i "X-Frame-Options"; then check_pass "Header X-Frame-Options presente."; else check_fail "Header X-Frame-Options AUSENTE."; fi
if echo "$HEADERS" | grep -q -i "X-Content-Type-Options: nosniff"; then check_pass "Header X-Content-Type-Options (nosniff) presente."; else check_fail "Header X-Content-Type-Options (nosniff) AUSENTE."; fi
if echo "$HEADERS" | grep -q -i "Content-Security-Policy"; then check_pass "Header CSP presente."; else check_fail "Header Content-Security-Policy (CSP) AUSENTE."; fi
if echo "$HEADERS" | grep -q -i "Referrer-Policy"; then check_pass "Header Referrer-Policy presente."; else check_fail "Header Referrer-Policy AUSENTE."; fi
if echo "$HEADERS" | grep -q -i "Set-Cookie"; then
    if ! echo "$HEADERS" | grep -i "HttpOnly"; then check_fail "Cookie de Sessão sem a flag 'HttpOnly'."; else check_pass "Flag 'HttpOnly' encontrada."; fi
    if ! echo "$HEADERS" | grep -i "Secure"; then check_fail "Cookie de Sessão sem a flag 'Secure'."; else check_pass "Flag 'Secure' encontrada."; fi
else check_info "Nenhum cookie de sessão detectado nesta URL."; fi
if echo "$HEADERS" | grep -q -i "Access-Control-Allow-Origin: *"; then check_fail "CORS inseguro (Access-Control-Allow-Origin: *) detectado."; else check_pass "Configuração de CORS não está perigosamente aberta (*)."; fi
if echo "$HEADERS" | grep -q -i "Server:"; then check_fail "Vazamento de Banner de Servidor (Server:) detectado."; else check_pass "Banner de Servidor (Server:) está oculto."; fi
if echo "$HEADERS" | grep -q -i "X-Powered-By:"; then check_fail "Vazamento de Banner de Tecnologia (X-Powered-By:) detectado."; else check_pass "Banner de Tecnologia (X-Powered-By:) está oculto."; fi

# ==========================================================
# 3. VERIFICAÇÕES DNS (Ferramenta: dig @1.1.1.1 +tcp)
# ==========================================================
echo -e "\n[+] Checando Saúde de DNS (para $ROOT_DOMAIN)..."
if $DNS_CMD txt "$ROOT_DOMAIN" | grep -q -i "v=spf1"; then check_pass "Registro SPF encontrado."; else check_fail "Registro SPF (DNS TXT) AUSENTE."; fi
if $DNS_CMD txt "_dmarc.$ROOT_DOMAIN" | grep -q -i "v=DMARC1"; then check_pass "Registro DMARC encontrado."; else check_fail "Registro DMARC (DNS TXT) AUSENTE."; fi
if $DNS_CMD DNSKEY "$ROOT_DOMAIN" | grep -q "257"; then check_pass "Registro DNSSEC (KSK) encontrado."; else check_fail "Registro DNSSEC (DNSKEY) AUSENTE."; fi
if $DNS_CMD CAA "$ROOT_DOMAIN" | grep -q "issue"; then check_pass "Registro CAA encontrado."; else check_fail "Registro CAA AUSENTE."; fi

# ==========================================================
# 4. ARQUIVOS EXPOSTOS E CONFIGS (Ferramenta: nuclei)
# ==========================================================
echo -e "\n[+] Checando Arquivos Expostos (Ferramenta: nuclei)..."
UA_FAKE="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
NUCLEI_COMMON_ARGS="-silent -retries 1 -timeout 5 -H \"$UA_FAKE\""
if nuclei $NUCLEI_COMMON_ARGS -tid "env-file" -u "$TARGET_URL" | grep -q "env-file"; then check_fail "Arquivo /.env acessível."; else check_pass "Arquivo /.env não está acessível."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "git-config" -u "$TARGET_URL" | grep -q "git-config"; then check_fail "Arquivo /.git/config acessível."; else check_pass "Arquivo /.git/config não está acessível."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "docker-compose-legacy" -u "$TARGET_URL" | grep -q "docker-compose"; then check_fail "Arquivo /docker-compose.yml acessível."; else check_pass "Arquivo /docker-compose.yml acessível."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "wp-admin-panel" -u "$TARGET_URL" | grep -q "wp-admin-panel"; then check_fail "Painel /wp-admin/ detectado."; else check_pass "Painel /wp-admin/ não detectado."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "jenkins-login" -u "$TARGET_URL" | grep -q "jenkins-login"; then check_fail "Painel /jenkins/login detectado."; else check_pass "Painel /jenkins/login não detectado."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "robots-txt-admin" -u "$TARGET_URL" | grep -q "robots-txt-admin"; then check_fail "Arquivo /robots.txt expondo rotas sensíveis."; else check_pass "Arquivo /robots.txt não expõe rotas de admin."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "security-txt" -u "$TARGET_URL" | grep -q "security-txt"; then check_pass "Arquivo /.well-known/security.txt encontrado."; else check_fail "Arquivo /.well-known/security.txt AUSENTE."; fi
if nuclei $NUCLEI_COMMON_ARGS -tid "htaccess" -u "$TARGET_URL" | grep -q "htaccess"; then check_fail "Arquivo /.htaccess acessível."; else check_pass "Arquivo /.htaccess não está acessível."; fi

# ==========================================================
# 5. TESTES EXTRAS (HTTP/DNS)
# ==========================================================
echo -e "\n[+] Checando Testes Extras (Redirect, Métodos, Takeover)..."

# 5.1 Subdomain Takeover (CNAME Simples)
CNAME_RECORD=$($DNS_CMD cname "$HOSTNAME")
if [ -n "$CNAME_RECORD" ]; then
    if ! $DNS_CMD A "$CNAME_RECORD" &> /dev/null; then check_fail "Potencial Subdomain Takeover (CNAME $CNAME_RECORD não resolve)."; else check_pass "CNAME do host principal resolve."; fi
else check_info "Nenhum CNAME encontrado para o host principal (normal)."; fi

# 5.2 HTTP -> HTTPS Redirect (usando curl)
HTTP_URL="http://$HOSTNAME"
FINAL_URL=$(curl -s -L -o /dev/null -w '%{url_effective}' "$HTTP_URL")
if echo "$FINAL_URL" | grep -q "https"; then
    check_pass "Redirect de HTTP para HTTPS está funcionando."
else
    check_fail "Redirect de HTTP para HTTPS AUSENTE."
fi

# 5.3 Métodos HTTP (usando curl)
METHODS=$(curl -s -I -L -k -X OPTIONS "$TARGET_URL" | grep -i "Allow:" | cut -d' ' -f2-)
if [ -n "$METHODS" ]; then
    if echo "$METHODS" | grep -q -E "(PUT|DELETE|PATCH|TRACE)"; then check_fail "Métodos HTTP perigosos (PUT/DELETE/TRACE) habilitados: $METHODS"; else check_pass "Métodos HTTP permitidos parecem seguros: $METHODS"; fi
else check_info "Servidor não respondeu ao OPTIONS (normal)."; fi

# --- CONCLUSÃO ---
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo -e "\n${YELLOW}--- Scan v2.2 Concluído em $TOTAL_TIME segundos ---${NC}"
