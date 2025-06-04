import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import nmap
import re
import shutil

# Configuração de logging
# Define o nível de log para INFO e o formato da mensagem
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Inicializa a aplicação Flask
app = Flask(__name__)
# Permite requisições de Cross-Origin Resource Sharing (CORS) de qualquer origem.
# Essencial para que o frontend (rodando em uma porta diferente) possa se comunicar com o backend.
CORS(app)

def is_nmap_installed():
    """
    Verifica se o executável do Nmap está disponível no PATH do sistema.
    Isso é crucial, pois a biblioteca python-nmap é apenas um wrapper para o Nmap real.
    """
    return shutil.which("nmap") is not None

def extract_cves(vulners_output):
    """
    Extrai Common Vulnerabilities and Exposures (CVEs) de uma string de saída
    do script 'vulners' do Nmap.
    Usa uma expressão regular para encontrar padrões como 'CVE-YYYY-NNNNN'.
    """
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)
    return cve_pattern.findall(vulners_output)

def run_scan(target, speed, port_option, os_detection):
    """
    Executa a varredura Nmap no alvo especificado com as opções fornecidas.
    
    Args:
        target (str): O endereço IP ou range de IPs a ser escaneado.
        speed (str): A velocidade do scan (ex: 'T4', 'T3').
        port_option (str): Opção de portas ('top_100', 'top_1000', 'all_ports', 'top_20').
        os_detection (bool): True para ativar a detecção de sistema operacional.
    
    Returns:
        list: Uma lista de dicionários contendo os resultados do scan para cada host.
    
    Raises:
        FileNotFoundError: Se o Nmap não estiver instalado.
        ValueError: Se houver um erro na execução do Nmap (ex: target inválido, permissões).
        RuntimeError: Para outros erros inesperados durante a varredura.
    """
    # Verifica se o Nmap está instalado antes de tentar usá-lo
    if not is_nmap_installed():
        logging.error("Nmap não encontrado. Certifique-se de que está instalado e no PATH.")
        raise FileNotFoundError("Nmap não está instalado ou não está acessível no PATH do sistema.")

    # Inicializa o objeto PortScanner do nmap
    nm = nmap.PortScanner()
    # Lista para armazenar os argumentos do Nmap
    arguments = [f"-{speed}"]

    # Adiciona a detecção de versão de serviço (-sV) aos argumentos.
    # Isso é essencial para obter informações detalhadas sobre produto e versão dos serviços.
    arguments.append("-sV")
    logging.info("Detecção de versão de serviço (-sV) ativada.")

    # Configura as opções de portas com base na escolha do usuário
    # NOVO: Adicionado 'top_20'
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
        # Fallback para uma opção padrão e loga um aviso se a opção for inválida
        logging.warning(f"Opção de porta inválida: {port_option}. Usando padrão (top_1000).")
        arguments.append("--top-ports 1000")

    # Adiciona a detecção de Sistema Operacional (-O) se solicitado pelo frontend.
    # Nota: A detecção de OS pode exigir privilégios de root.
    if os_detection:
        arguments.append("-O")
        logging.info("Detecção de OS ativada. Isso pode exigir privilégios de root.")

    # Adiciona o script de vulnerabilidades 'vulners' para buscar CVEs.
    arguments.append("--script vulners")
    
    # Converte a lista de argumentos em uma única string para o Nmap
    full_arguments = " ".join(arguments)
    logging.info(f"Executando Nmap no target: {target} com argumentos: {full_arguments}")

    try:
        # Executa o scan do Nmap
        nm.scan(hosts=target, arguments=full_arguments)
    except nmap.PortScannerError as e:
        # Captura erros específicos do Nmap (ex: argumentos inválidos, problemas de permissão)
        logging.error(f"Erro do Nmap ao escanear {target}: {e}")
        raise ValueError(f"Erro ao executar o Nmap. Verifique o target ou as permissões: {e}")
    except Exception as e:
        # Captura quaisquer outros erros inesperados durante a execução do scan
        logging.error(f"Erro inesperado durante a varredura do Nmap em {target}: {e}")
        raise RuntimeError(f"Ocorreu um erro inesperado durante a varredura: {e}")

    results = []
    # Verifica se algum host foi encontrado pelo scan
    if not nm.all_hosts():
        logging.info(f"Nenhum host encontrado para o target: {target}")
        return results

    # Itera sobre cada host encontrado no scan
    for host in nm.all_hosts():
        services = []
        # Inicializa um dicionário para armazenar informações detalhadas do OS
        os_details = {
            "name": "Não detectado",
            "family": "Não detectado",
            "generation": "Não detectado",
            "accuracy": None,
            "cpe": []
        }
        
        # Tenta obter informações detalhadas do OS se 'osmatch' estiver presente
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            # Pega o primeiro 'osmatch' que geralmente é o mais preciso
            first_osmatch = nm[host]['osmatch'][0]
            os_details["name"] = first_osmatch.get('name', 'Não detectado')
            
            # Extrai detalhes mais granulares da classe do OS
            os_class = first_osmatch.get('osclass', [{}])[0] # osclass é uma lista de dicionários
            os_details["family"] = os_class.get('osfamily', 'Não detectado')
            os_details["generation"] = os_class.get('osgen', 'Não detectado')
            os_details["accuracy"] = first_osmatch.get('accuracy')
            os_details["cpe"] = os_class.get('cpe', [])

            # Loga a informação de OS detectada
            logging.info(f"OS detectado para {host}: {os_details['name']}")
            # Loga os detalhes brutos do osmatch para depuração, se necessário
            # logging.info(f"Detalhes brutos do OS para {host} (osmatch): {first_osmatch}")
        elif 'os' in nm[host]:
            # Este bloco lida com casos onde 'osmatch' não está presente, mas 'os' está.
            # Geralmente, 'os' contém uma string menos estruturada.
            logging.info(f"Nmap encontrou dados de OS, mas sem 'osmatch' para {host}. Dados brutos: {nm[host]['os']}")
            # Para manter a consistência, não tentamos parsear a string 'os' aqui para o dicionário estruturado.
            # O frontend ainda receberá "Não detectado" para family/generation, mas o log terá o bruto.
        else:
            logging.info(f"Nenhuma informação de OS disponível para {host}.")

        # Itera sobre os protocolos (tcp, udp) e portas para cada host
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports): # Ordena as portas para uma saída consistente
                service = nm[host][proto][port]
                cves = []

                # Verifica se o script 'vulners' rodou e extrai as CVEs
                script_output = service.get('script', {})
                if 'vulners' in script_output:
                    cves = extract_cves(script_output['vulners'])
                    if cves:
                        logging.info(f"CVEs encontradas para {host}:{port} - {cves}")

                # Adiciona os detalhes do serviço à lista de serviços
                services.append({
                    "port": port,
                    "protocol": proto,
                    "name": service.get('name', 'unknown'),
                    "state": service.get('state', 'unknown'),
                    "product": service.get('product', ''), # Preenchido com -sV
                    "version": service.get('version', ''), # Preenchido com -sV
                    "extrainfo": service.get('extrainfo', ''),
                    "cpes": service.get('cpe', []),
                    "cves": cves
                })
        
        # Obtém o status do host (up/down)
        host_status = nm[host].state()
        logging.info(f"Host {host} está {host_status}")

        # Adiciona os resultados do host à lista geral de resultados
        results.append({
            "ip": host,
            "hostname": nm[host].hostname(),
            "os_summary": os_details["name"], # Resumo do OS para exibição principal
            "os_details": os_details,         # Detalhes completos do OS
            "status": host_status,
            "services": services
        })

    return results

# ---
## **Rotas da API**
# ---

@app.route('/scan', methods=['POST'])
def scan():
    """
    Endpoint para iniciar a varredura Nmap.
    Recebe dados JSON do frontend com target, velocidade, opções de porta e detecção de OS.
    """
    data = request.get_json()
    # Valida se os dados JSON foram recebidos
    if not data:
        logging.warning("Requisição POST sem dados JSON.")
        return jsonify({"error": "Dados JSON inválidos na requisição."}), 400

    # Extrai os parâmetros da requisição JSON
    target = data.get('target')
    speed = data.get('speed')
    port_option = data.get('port_option')
    os_detection = data.get('os_detection', False) # Default para False se não for fornecido

    # Valida se os campos obrigatórios estão presentes
    if not target or not speed or not port_option:
        logging.warning(f"Campos obrigatórios faltando: target={target}, speed={speed}, port_option={port_option}")
        return jsonify({"error": "Campos 'target', 'speed' e 'port_option' são obrigatórios."}), 400

    logging.info(f"Recebida solicitação de scan para target: {target}, speed: {speed}, port_option: {port_option}, os_detection: {os_detection}")

    try:
        # Chama a função run_scan para executar a varredura
        results = run_scan(target, speed, port_option, os_detection)
        # Se nenhum resultado for encontrado, retorna uma mensagem informativa
        if not results:
            return jsonify({"message": "Scan concluído, mas nenhum resultado encontrado para o target especificado. O host pode estar offline ou inacessível."}), 200
        # Retorna os resultados em formato JSON com status 200 OK
        return jsonify({"results": results}), 200
    except FileNotFoundError as e:
        # Retorna erro 500 se o Nmap não for encontrado
        return jsonify({"error": str(e)}), 500
    except ValueError as e:
        # Retorna erro 400 para problemas de execução do Nmap (ex: argumentos inválidos)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        # Captura e loga quaisquer outros erros inesperados do servidor
        logging.exception("Erro inesperado durante a rota /scan:") # Registra o traceback completo
        return jsonify({"error": f"Erro interno do servidor ao realizar a análise. Detalhes: {e}"}), 500

# ---
## **Execução da Aplicação**
# ---

if __name__ == '__main__':
    # Realiza uma verificação inicial do Nmap ao iniciar o servidor
    if not is_nmap_installed():
        logging.error("ATENÇÃO: Nmap não está instalado ou não está no PATH do sistema. A funcionalidade de scan não funcionará.")
    else:
        logging.info("Nmap detectado. O servidor está pronto para varreduras.")

    # Inicia o servidor Flask.
    # host='0.0.0.0' permite que o servidor seja acessível de qualquer IP na rede.
    # port=5000 define a porta.
    # debug=True ativa o modo de depuração (recarrega o servidor em mudanças, mostra debugger).
    # IMPORTANTE: debug=True deve ser usado APENAS em desenvolvimento, nunca em produção!
    app.run(host='0.0.0.0', port=5000, debug=True)
