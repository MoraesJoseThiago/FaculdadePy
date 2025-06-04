#Cria um ambiente isolado especificamente para Python 3.
python3 -m venv venv_scan

##Ativa esse ambiente, fazendo com que qualquer python ou pip que você use aponte para a versão 3 dentro desse ambiente.
source venv_scan/bin/activate

## Agora, quando você usa pip (sem o 3 porque ele já está no ambiente de Python 3), ele instala tudo no lugar certo, dentro do ambiente virtual de Python 3.
pip install Flask Flask-Cors python-nmap

##Quando você roda python (sem o 3, porque ele já está no ambiente de Python 3), ele executa seu script com o Python 3 e consegue encontrar todas as bibliotecas que foram instaladas no passo anterior.
python api.py
