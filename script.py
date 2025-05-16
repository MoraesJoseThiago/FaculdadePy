#!/usr/bin/env python3

import subprocess
import ipaddress
import re
import time
import csv
import os

def verificar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def processar_entrada(entrada):
    if verificar_ip(entrada):
        return [entrada], entrada
    
    try:
        rede = ipaddress.ip_network(entrada, strict=False)
        return [str(ip) for ip in rede.hosts()], entrada.split('/')[0]
    except ValueError:
        pass
    
    if '-' in entrada:
        partes = entrada.split('-')
        if len(partes) == 2 and verificar_ip(partes[0]):
            base = partes[0].rsplit('.', 1)[0]
            try:
                inicio = int(partes[0].split('.')[-1])
                fim = int(partes[1])
                if 0 <= inicio <= 255 and 0 <= fim <= 255 and inicio <= fim:
                    nome_arquivo = f"{partes[0]}-{fim}" if fim > inicio else partes[0]
                    return [f"{base}.{i}" for i in range(inicio, fim + 1)], nome_arquivo
            except ValueError:
                pass
    
    return None, None

def selecionar_velocidade():
    print("\nSelecione a velocidade do scan:")
    print("1 - Scan Lento (T1) - Muito discreto")
    print("2 - Scan Médio (T3) - Equilibrado")
    print("3 - Scan Rápido (T4) - Mais agressivo")
    
    while True:
        opcao = input("Opção (1-3): ")
        if opcao in ['1', '2', '3']:
            return {'1': '-T1', '2': '-T3', '3': '-T4'}[opcao]
        print("Opção inválida! Digite 1, 2 ou 3")

def selecionar_portas():
    print("\nSelecione o range de portas:")
    print("1 - TOP 20 portas mais comuns")
    print("2 - 1000 portas comumente usadas (padrão)")
    print("3 - Todas as portas (1-65535)")
    
    while True:
        opcao = input("Opção (1-3): ")
        if opcao == '1':
            return '--top-ports 20'
        elif opcao == '2':
            return ''
        elif opcao == '3':
            return '-p-'
        print("Opção inválida! Digite 1, 2 ou 3")

def host_esta_ativo(ip):
    print(f"\n[*] Testando conectividade com: {ip}", end='', flush=True)
    comando = f"ping -c 3 -W 1 {ip}"
    try:
        resultado = subprocess.run(comando, shell=True, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                text=True)
        
        if "3 received" in resultado.stdout:
            print(" [ATIVO]")
            return True
        elif "1 received" in resultado.stdout:
            print(" [RESPOSTA PARCIAL]")
            return True
        else:
            print(" [INATIVO]")
            return False
    except subprocess.CalledProcessError:
        print(" [ERRO]")
        return False

def scan_portas(ip, velocidade, portas):
    print(f"[+] Iniciando scan avançado em: {ip}")
    
    # Adicionado -sV para detecção de versões
    comando = f"nmap {velocidade} -O -sS -sV --open --script=banner {portas} {ip}"
    try:
        resultado = subprocess.run(comando, shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True)
        
        if resultado.returncode == 0:
            return resultado.stdout
        return None
    except subprocess.CalledProcessError as e:
        print(f"Erro no scan: {e.stderr}")
        return None

def extrair_informacoes(resultado_nmap):
    informacoes = {
        'os': 'Não detectado',
        'mac': 'Não disponível',
        'servicos': [],
        'portas': [],
        'versoes': {}  # Novo campo para versões dos serviços
    }
    
    linhas = resultado_nmap.split('\n')
    porta_atual = None
    
    for linha in linhas:
        if 'OS details:' in linha:
            informacoes['os'] = linha.split(':', 1)[1].strip()
        elif 'Running:' in linha:
            informacoes['os'] = linha.split(':', 1)[1].strip()
        
        if 'MAC Address:' in linha:
            informacoes['mac'] = linha.split(':', 1)[1].strip()
        
        if 'Service Info:' in linha:
            servico = linha.split(':', 1)[1].strip()
            if servico not in informacoes['servicos']:
                informacoes['servicos'].append(servico)
        
        # Extrai informações de versão (ex: "80/tcp open  http    Apache httpd 2.4.41")
        match = re.match(r'^(\d+/tcp\s+open\s+\w+)\s+(.*)$', linha)
        if match:
            porta_info = match.group(1)
            versao_info = match.group(2).strip()
            informacoes['portas'].append(f"{porta_info} ({versao_info})" if versao_info else porta_info)
            if versao_info and porta_atual:
                informacoes['versoes'][porta_atual] = versao_info
        
        # Identifica a porta atual para associar com a versão
        porta_match = re.match(r'^(\d+)/', linha)
        if porta_match:
            porta_atual = porta_match.group(1)
    
    return informacoes

def salvar_csv(nome_base, dados):
    nome_arquivo = f"{nome_base.replace('/', '_')}.csv"
    
    with open(nome_arquivo, mode='w', newline='') as arquivo:
        writer = csv.writer(arquivo)
        
        # Cabeçalho atualizado com versões
        writer.writerow(['IP', 'Sistema Operacional', 'Endereço MAC', 'Serviços', 'Portas Abertas', 'Versões Detectadas'])
        
        for host in dados:
            # Formata as versões para exibição
            versoes_formatadas = []
            for porta, versao in host['versoes'].items():
                versoes_formatadas.append(f"Porta {porta}: {versao}")
            
            writer.writerow([
                host['ip'],
                host['os'],
                host['mac'],
                '; '.join(host['servicos']),
                '; '.join(host['portas']),
                ' | '.join(versoes_formatadas) if versoes_formatadas else 'Nenhuma'
            ])
    
    print(f"\n[+] Relatório completo salvo em: {nome_arquivo}")

def mostrar_resultados(ip, informacoes):
    print(f"\n[RESULTADO DETALHADO] Host: {ip}")
    print(f"Sistema Operacional: {informacoes['os']}")
    print(f"Endereço MAC: {informacoes['mac']}")
    
    if informacoes['servicos']:
        print("\nServiços detectados:")
        for servico in informacoes['servicos']:
            print(f"  - {servico}")
    
    if informacoes['portas']:
        print("\nPortas abertas e versões:")
        for porta in informacoes['portas']:
            print(f"  {porta}")
    else:
        print("\nNenhuma porta aberta encontrada.")
    
    print("\n" + "="*50)

def main():
    print("\n=== Scanner de Rede Avançado ===")
    print("Com detecção de versões de serviços (-sV)\n")
    
    velocidade = selecionar_velocidade()
    portas = selecionar_portas()
    
    print("\nFormatos aceitos:")
    print("- IP único (ex: 192.168.1.1)")
    print("- Range CIDR (ex: 192.168.1.0/24)")
    print("- Range com hífen (ex: 172.16.9.201-225)")
    
    while True:
        entrada = input("\nAlvo (digite 'sair' para encerrar): ").strip()
        
        if entrada.lower() == 'sair':
            print("\nEncerrando scanner...")
            break
            
        ips, nome_base = processar_entrada(entrada)
        if not ips:
            print("Formato inválido. Use os formatos especificados.")
            continue
            
        print(f"\nIniciando varredura em {len(ips)} hosts...")
        
        resultados = []
        
        for ip in ips:
            if host_esta_ativo(ip):
                resultado = scan_portas(ip, velocidade, portas)
                if resultado:
                    informacoes = extrair_informacoes(resultado)
                    informacoes['ip'] = ip
                    mostrar_resultados(ip, informacoes)
                    resultados.append(informacoes)
                time.sleep(1)
        
        if resultados:
            salvar_csv(nome_base, resultados)

if __name__ == "__main__":
    main()
