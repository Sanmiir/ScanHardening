# ScanHardening

Este projeto contém um script em Bash para realizar verificações básicas de hardening em um domínio ou aplicação web.  
O foco é executar checagens rápidas de SSL/TLS, headers HTTP, cookies de segurança, configurações DNS e alguns testes comuns de exposição de arquivos e serviços.

O objetivo do script é auxiliar em avaliações iniciais de segurança e reconhecimento de superfície de ataque.

---

## Dependências

As ferramentas necessárias são:

- curl  
- dig  
- sslscan  
- nuclei  

Instalação (Debian/Kali/Ubuntu):

```bash
apt install curl dnsutils sslscan nuclei
nuclei -update-templates

```
## Uso

Execute o script passando o domínio ou host como parâmetro (sem https://).

Exemplo:
```bash
./scanHardening.sh exemplo.com
```
O script irá realizar:

verificações de protocolos e cifras SSL/TLS

análise de headers HTTP

inspeção de cookies de sessão

checagens de DNS (SPF, DMARC, DNSSEC, CAA)

## Finalidade

O script serve como ferramenta de suporte para análises rápidas em processos de pentest, hardening e monitoração de superfícies de ataque.
Não substitui scanners completos, mas oferece uma visão imediata de configurações incorretas ou pontos de atenção.

testes de exposição de arquivos comuns (usando nuclei)

validações básicas adicionais (CNAME, redirecionamentos, métodos HTTP)
