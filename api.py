import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import nmap
import re
import shutil
import requests
import time

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)

# Cache em memória para os detalhes das CVEs do NVD
cve_details_cache = {}
# Tempo de espera inicial entre as requisições ao NVD (em segundos)
NVD_API_DELAY = 5.0 # Atraso de 5 segundos para ser BEM conservador (1 requisição a cada 5s)
MAX_NVD_RETRIES = 3 # Número máximo de tentativas de consulta ao NVD para uma única CVE

# Limite de CVEs (qualquer severidade) para as quais buscar detalhes no NVD por scan.
# Isso evita o erro 429 para scans com muitas CVEs.
MAX_NVD_DETAILS_FETCHED_PER_SCAN = 15 # Buscar detalhes para as primeiras 15 CVEs.

def is_nmap_installed():
    """Verifica se o executável do Nmap está disponível no PATH do sistema."""
    return shutil.which("nmap") is not None

def extract_cves(vulners_output):
    """Extrai Common Vulnerabilities and Exposures (CVEs) de uma string de saída do script 'vulners' do Nmap."""
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)
    return cve_pattern.findall(vulners_output)

def get_cve_severity_from_nvd(cve_id):
    """
    Consulta a API do NVD para obter detalhes da CVE, incluindo severidade e pontuação CVSS.
    Retorna (detalhes_da_cve, True/False se foi buscado_do_nvd_agora).
    """
    if cve_id in cve_details_cache:
        logging.info(f"CVE {cve_id} encontrada no cache.")
        return cve_details_cache[cve_id], False # Retorna do cache, não foi buscado agora

    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    default_cve_details = {
        "severity": "unknown",
        "cvss_score": None,
        "summary": "Detalhes não puderam ser obtidos do NVD ou consulta ignorada por limite.",
        "references": []
    }

    retries = 0
    while retries <= MAX_NVD_RETRIES:
        try:
            # APLICAR DELAY ANTES DE CADA REQUISIÇÃO AO NVD
            current_delay = NVD_API_DELAY * (2 ** retries) # Atraso exponencial
            if retries > 0:
                logging.info(f"Tentando novamente consulta NVD para {cve_id} (tentativa {retries+1}/{MAX_NVD_RETRIES}), atraso: {current_delay:.2f}s")
            time.sleep(current_delay)

            response = requests.get(nvd_api_url, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data and data.get('vulnerabilities'):
                vuln_data = data['vulnerabilities'][0]['cve']
                
                cvss_score = None
                if 'metrics' in vuln_data:
                    if 'cvssMetricV31' in vuln_data['metrics'] and vuln_data['metrics']['cvssMetricV31']:
                        cvss_score = vuln_data['metrics']['cvssMetricV31'][0]['cvssData'].get('baseScore')
                    elif 'cvssMetricV30' in vuln_data['metrics'] and vuln_data['metrics']['cvssMetricV30']:
                        cvss_score = vuln_data['metrics']['cvssMetricV30'][0]['cvssData'].get('baseScore')
                    elif 'cvssMetricV2' in vuln_data['metrics'] and vuln_data['metrics']['cvssMetricV2']:
                        cvss_score = vuln_data['metrics']['cvssMetricV2'][0]['cvssData'].get('baseScore')
            
            description = "Descrição não disponível."
            if 'descriptions' in vuln_data:
                for desc in vuln_data['descriptions']:
                    if desc['lang'] == 'en':
                        description = desc['value']
                        break
            
            severity_category = "low"
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity_category = "critical"
                elif cvss_score >= 7.0:
                    severity_category = "high"
                elif cvss_score >= 4.0:
                    severity_category = "medium"
                else:
                    severity_category = "low"
            else:
                severity_category = "unknown"

            result = {
                "severity": severity_category,
                "cvss_score": cvss_score,
                "summary": description,
                "references": [ref['url'] for ref in vuln_data.get('references', []) if 'url' in ref]
            }
            cve_details_cache[cve_id] = result
            return result, True # Detalhes obtidos do NVD agora

        except requests.exceptions.Timeout:
            logging.error(f"Timeout ao consultar NVD para {cve_id} (tentativa {retries+1}/{MAX_NVD_RETRIES}).")
        except requests.exceptions.RequestException as req_err:
            if "429 Client Error" in str(req_err):
                logging.warning(f"Limite de requisições NVD atingido para {cve_id} (tentativa {retries+1}/{MAX_NVD_RETRIES}).")
            else:
                logging.error(f"Erro de requisição ao consultar NVD para {cve_id}: {req_err} (tentativa {retries+1}/{MAX_NVD_RETRIES}).")
        except (KeyError, IndexError) as ke:
            logging.warning(f"Estrutura inesperada na resposta do NVD para {cve_id} (KeyError/IndexError): {ke}")
            logging.debug(f"Resposta NVD para {cve_id}: {data}")
        except Exception as e:
            logging.error(f"Erro genérico ao processar resposta do NVD para {cve_id}: {e}")
        
        retries += 1
    
    logging.error(f"Todas as {MAX_NVD_RETRIES} tentativas de consulta ao NVD para {cve_id} falharam. Retornando detalhes padrão.")
    cve_details_cache[cve_id] = default_cve_details # Cacheia o default para não tentar de novo
    return default_cve_details, False # Não foi buscado agora, falhou

def run_scan(target, speed, port_option, os_detection):
    """Executa a varredura Nmap no alvo especificado com as opções fornecidas."""
    if not is_nmap_installed():
        logging.error("Nmap não encontrado. Certifique-se de que está instalado e no PATH.")
        raise FileNotFoundError("Nmap não está instalado ou não está acessível no PATH do sistema.")

    nm = nmap.PortScanner()
    arguments = [f"-{speed}"]
    arguments.append("-sV")
    logging.info("Detecção de versão de serviço (-sV) ativada.")
    if port_option == "top_20":
        arguments.append("--top-ports 20")
        logging.info("Varredura nas 20 portas mais comuns ativada.")
    elif port_option == "top_100":
        arguments.append("--top-ports 100")
        logging.info("Varredura nas 100 portas mais comuns ativada.")
    elif port_option == "top_1000":
        arguments.append("--top-ports 1000")
        logging.info("Varredura nas 1000 portas mais comuns ativada.")
    elif port_option == "all_ports":
        arguments.append("-p-")
        logging.info("Varredura em todas as portas ativada.")
    else:
        logging.warning(f"Opção de porta inválida: {port_option}. Usando padrão (top_1000).")
        arguments.append("--top-ports 1000")
    if os_detection:
        arguments.append("-O")
        logging.info("Detecção de OS ativada. Isso pode exigir privilégios de root.")
    arguments.append("--script vulners")
    full_arguments = " ".join(arguments)
    logging.info(f"Executando Nmap no target: {target} com argumentos: {full_arguments}")

    try:
        nm.scan(hosts=target, arguments=full_arguments)
    except nmap.PortScannerError as e:
        logging.error(f"Erro do Nmap ao escanear {target}: {e}")
        raise ValueError(f"Erro ao executar o Nmap. Verifique o target ou as permissões: {e}")
    except Exception as e:
        logging.error(f"Erro inesperado durante a varredura do Nmap em {target}: {e}")
        raise RuntimeError(f"Ocorreu um erro inesperado durante a varredura: {e}")

    results = []
    if not nm.all_hosts():
        logging.info(f"Nenhum host encontrado para o target: {target}")
        return results

    # Contador para detalhes de CVEs obtidos do NVD nesta execução do scan
    nvd_details_fetched_count = 0 

    for host in nm.all_hosts():
        services = []
        os_details = {
            "name": "Não detectado", "family": "Não detectado", "generation": "Não detectado", "accuracy": None, "cpe": []
        }
        
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            first_osmatch = nm[host]['osmatch'][0]
            os_details["name"] = first_osmatch.get('name', 'Não detectado')
            os_class = first_osmatch.get('osclass', [{}])[0]
            os_details["family"] = os_class.get('osfamily', 'Não detectado')
            os_details["generation"] = os_class.get('osgen', 'Não detectado')
            os_details["accuracy"] = first_osmatch.get('accuracy')
            os_details["cpe"] = os_class.get('cpe', [])
            logging.info(f"OS detectado para {host}: {os_details['name']}")
        elif 'os' in nm[host]:
            logging.info(f"Nmap encontrou dados de OS, mas sem 'osmatch' para {host}. Dados brutos: {nm[host]['os']}")
        else:
            logging.info(f"Nenhuma informação de OS disponível para {host}.")

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                cve_ids_from_nmap_raw = extract_cves(service.get('script', {}).get('vulners', ''))
                unique_cve_ids_for_service = list(set(cve_ids_from_nmap_raw))

                detailed_cves = []
                for cve_id in unique_cve_ids_for_service:
                    cve_details = None
                    fetched_now = False # Flag para saber se a consulta ao NVD foi feita agora

                    # NOVO: Se o limite de detalhes de CVEs foi atingido, não faz a requisição ao NVD
                    if nvd_details_fetched_count >= MAX_NVD_DETAILS_FETCHED_PER_SCAN:
                        logging.warning(f"Limite total de detalhes de CVEs ({MAX_NVD_DETAILS_FETCHED_PER_SCAN}) atingido para este scan. Detalhes para {cve_id} e subsequentes não serão consultados do NVD.")
                        cve_details = {
                            "id": cve_id,
                            "severity": "unknown",
                            "cvss_score": None,
                            "summary": "Detalhes não consultados devido ao limite de requisições ao NVD para este scan.",
                            "references": []
                        }
                        fetched_now = False # Não foi buscado agora, foi ignorado
                    else:
                        cve_details, fetched_now = get_cve_severity_from_nvd(cve_id) # Chama a função para obter detalhes

                    # Se a consulta ao NVD foi bem-sucedida e não veio do cache, incrementa o contador
                    if fetched_now: # Este é o ponto crucial para o controle preciso
                        nvd_details_fetched_count += 1

                    detailed_cves.append({
                        "id": cve_id,
                        "severity": cve_details["severity"],
                        "cvss_score": cve_details["cvss_score"],
                        "summary": cve_details["summary"],
                        "references": cve_details["references"]
                    })
                    if cve_details["severity"] != "unknown" and cve_details["summary"] != "Detalhes não puderam ser obtidos do NVD ou consulta ignorada por limite.": 
                        logging.info(f"CVE {cve_id} (Sev: {cve_details['severity']}, CVSS: {cve_details['cvss_score']}) encontrada para {host}:{port}")
                    else:
                        logging.warning(f"Detalhes da CVE {cve_id} não obtidos para {host}:{port} ou consulta ignorada.")

                services.append({
                    "port": port, "protocol": proto, "name": service.get('name', 'unknown'),
                    "state": service.get('state', 'unknown'), "product": service.get('product', ''),
                    "version": service.get('version', ''), "extrainfo": service.get('extrainfo', ''),
                    "cpes": service.get('cpe', []), "cves": detailed_cves
                })
        
        host_status = nm[host].state()
        logging.info(f"Host {host} está {host_status}")

        results.append({
            "ip": host, "hostname": nm[host].hostname(), "os_summary": os_details["name"],
            "os_details": os_details, "status": host_status, "services": services
        })

    return results

# ---
## **Rotas da API**
# ---

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    if not data:
        logging.warning("Requisição POST sem dados JSON.")
        return jsonify({"error": "Dados JSON inválidos na requisição."}), 400

    target = data.get('target')
    speed = data.get('speed')
    port_option = data.get('port_option')
    os_detection = data.get('os_detection', False)

    if not target or not speed or not port_option:
        logging.warning(f"Campos obrigatórios faltando: target={target}, speed={speed}, port_option={port_option}")
        return jsonify({"error": "Campos 'target', 'speed' e 'port_option' são obrigatórios."}), 400

    logging.info(f"Recebida solicitação de scan para target: {target}, speed: {speed}, port_option: {port_option}, os_detection: {os_detection}")

    try:
        results = run_scan(target, speed, port_option, os_detection)
        if not results:
            return jsonify({"message": "Scan concluído, mas nenhum resultado encontrado para o target especificado. O host pode estar offline ou inacessível."}), 200
        return jsonify({"results": results}), 200
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.exception("Erro inesperado durante a rota /scan:")
        return jsonify({"error": f"Erro interno do servidor ao realizar a análise. Detalhes: {e}"}), 500

if __name__ == '__main__':
    if not is_nmap_installed():
        logging.error("ATENÇÃO: Nmap não está instalado ou não está no PATH do sistema. A funcionalidade de scan não funcionará.")
    else:
        logging.info("Nmap detectado. O servidor está pronto para varreduras.")

    app.run(host='0.0.0.0', port=5000, debug=True)

