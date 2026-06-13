# Contextualização

Esta seção se destina a introduzir o mecanismo de In-Band Network Telemetry [1], um hot topic em
pesquisa que surgiu com o advento de redes programáveis. INT permite a coleta de informações a
partir dos switches de uma rede, e pode ser utilizado por exemplo para identificar problemas de
desempenho e coletar métricas sobre o funcionamento da rede. A ideia geral é que os pacotes dos
end-hosts sejam monitorados obrigatoriamente pelos próprios switches. 

1) Todo pacote inserido na rede recebe necessariamente uma tag com um cabeçalho INT caso este
não esteja presente (passo A). Um exemplo de cabeçalho INT é ilustrado na Figura 2. Esta
verificação de existência do cabeçalho INT deve ser feita pelo switch e inserido obrigatoriamente
pelo switch caso não esteja presente. A inclusão de um cabeçalho pode ser feita usando a função
setValid no cabeçalho desejado (desde que seu nome esteja já incluso no deparser). Isto
garante que end-hosts não irão burlar o sistema não inserindo o cabeçalho INT.

2) A cada salto, o switch deverá ler todos os cabeçalhos. Para ler um número arbitrário de
cabeçalhos, será necessário fazer um controle de quantos cabeçalhos já foram colocados. Isto
será um dado importante no cabeçalho INT, que será usado por uma primitiva do parser.

3) Em seguida, o switch irá criar um cabeçalho filho ao cabeçalho INT (passos B & C). Este
cabeçalho filho terá seu próprio header type. Este cabeçalho filho conterá dados sobre a
condição do switch que deverão ser carregados pelo programa P4. Os dados a serem usados
serão escolhidos pelo programador. O cabeçalho filho do switch atual tem que ser colocado
após todos os cabeçalhos filhos anteriores que, por sua vez, serão colocados depois do
cabeçalho pai.

4) Quando estivermos no salto imediatamente anterior ao destino do pacote (passo D), é possível:
(i) deixar os cabeçalhos serem recebidos pela aplicação destino e interpretados por ela própria;
(ii) criar uma cópia do pacote (clone) e: remover os cabeçalhos INT do primeiro pacote, fazendo
assim com que o pacote seja entregue de forma transparente para a aplicação destino, sem que
esta saiba que o pacote foi monitorado e, para o segundo, remover todos os dados do payload
do pacote e enviar somente o cabeçalho para algum outro host, responsável pelo monitoramento
global da rede (telemetry analytics engine).

# ESPECIFICAÇÃO DO TRABALHO
Apresentadas as informações contextuais acima, e assumindo uma rede totalmente programável via
SDN/P4, projete e desenvolva um mecanismo que permita – via In-Band Network Telemetry [1] –
depurar precisamente problemas de desempenho em uma aplicação (i.e., conjunto de fluxos) de
interesse.
A ideia básica é que cada pacote desses fluxos, ao ingressar na rede, tenha um cabeçalho de
telemetria adicionado. A cada salto, incluindo o primeiro e o último, devem ser coletadas e
armazenadas (nos cabeçalhos INT) as “condições” de rede (e.g., timestamp, delay do salto,
tamanho da fila, porta de entrada e saída e fluxos competidores) observadas pelo pacote, além de
identificadores (e.g., ID do dispositivo). Ao chegar no end-host destino, o programa receptor
deverá identificar os cabeçalhos adicionados no pacote e informar as condições de rede capturadas
por ele.

## Requisitos Funcionais
1. Verificação da presença do cabeçalho INT pai e inclusão deste cabeçalho nos pacotes em
que ele não esteja presente.

2. Criação e inserção, a cada hop, de um cabeçalho INT filho.

3. Preenchimento dos campos dos cabeçalhos filhos com as informações dos switches
a. O subconjunto mínimo de métricas a serem coletadas é (mas métricas adicionais
são desejáveis):
i. Timestamp de entrada;
ii. Porta de entrada;
iii. Porta de saída;
iv. ID do switch.

4. Ao chegar no host destino, o host deverá ser capaz de, por software (no arquivo
receive.py), extrair as informações do pacote e separá-las do payload original do pacote.
a. E.g., se foram inseridos 20 bytes de cabeçalhos INT, o receive.py deverá separar
os 20 bytes INT do payload original e exibi-los de maneira distinta.

## Getting Started
1. Faça o download da máquina virtual com o ambiente P4 já previamente configurado e
disponibilizado para os alunos;
2. Baixe o zip da pasta TP-Protocolos (disponível no Moodle da disciplina) e descompacte-o
no local de sua preferência; acesse então, a pasta “TP-Protocolos/skeleton/TP-skel”;
3. Inicialize o Mininet usando “make” e teste a conectividade básica entre hosts:
a. Ao abrir o Mininet, use o comando “xterm h1 h2”;
b. Em um dos terminais, digite ifconfig e descubra o IP deste host. Logo após,
execute o arquivo receive.py;
c. Use o outro terminal para executar um “send.py <ip> <mensagem>” sendo <ip>
o IP do primeiro terminal e mensagem uma string. Se o pacote e a mensagem
aparecerem corretamente no receive.py, então há conectividade entre os dois
hosts (se houver perda da conectividade durante o processo de desenvolvimento,
significa que algo não foi feito da forma correta, e é sugerido sempre refazer esse
teste para não se perder);
4. Edite o arquivo basic.p4 para incluir o seu mecanismo de INT;
5. Edite o arquivo receive.py para receber e ler o seu cabeçalho INT;
6. Implemente seu mecanismo de INT de forma que este funcione para topologias genéricas, e
não somente para a topologia proposta para este trabalho.