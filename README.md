# Monitoramento-ddos

# 1.0 Explicação do código

 Foi criado com o intuito de monitorar o tráfego de entrada um servidor a partir dos pacotes enviados para o mesmo, através de um Ip. O monitoramento consiste na utilização da linguagem ruby com a gem 'packetfu' com o intuito de analisar de aquele IP está com possíveis inteções de DDOS.
 Para a realização desse código, foi imprescindível a utilização da gem 'packetfu' ótima para monitoramento de sockets, disponível como gem do ruby.

# 1.1 Gem

'Packetfu' é uma biblioteca/gem disponível no Ruby para análises de trafego, assim como a biblioteca sockets, ela é possível identificar atráves de um conjunto de ferrametas identificar um conjunto de comportamentos que por padrão são identificados em um ataque DOS ou DDOS, que consiste na sobrecarega de um servidor atráves no envio de pacotes. 

Pensando nisso, utilizei a biblioteca 'packetfu' por ser a que melhor se adapta nesse contexto de análise de tráfego.

# 2.0 Como funciona?

  ### 2.1 Função

 O código de forma introdutória começa a partir da criação de uma função responsável por criar um "Packetfu" de captura.

 captura = PacketFu::Capture.new(:iface => 'wlan0', :promisc => true) 

Colocamos dentro da variável 'captura' a função presente na biblioteca responsável por capturar trafego no hostserver.
Funções como 'iface' são responsáveis por pegar o tipo da rede, que podemos observar atráves de um comando no promt de comando, seja nos sistemas linux, mac, ou windows.

<pre><code>

Linux

ip a

Windows

ipconfig

MAC/OS

ifconfig

</code></pre>

### 2.2 Estrutura de dados e contagem

  Criação de uma estrutura de dados 'Hash' que realiza a contagem de quantas vezes o pácote foi enviado pelo mesmo IP.

<pre><code>
    contagem_pacotes_ip = Hash.new(0)
</code></pre>

### 2.3 Loop de pacotes

  Entramos agora no laço de repetição que capturamos os pacotes da rede.

<pre><code>
  begin
    loop do
      pacote_raw = captura.next  
</code></pre>
  Nesse loop feito com 'loop do' capturamos pacotes de baixo nível que podem incluir qualquer protocolo, e não protocolos especificos.
  A partir desse loop de recebimento de pacotes, realizamos condições para tratar a informação de cada pácote recebido.

<pre><code>
  if pacote.is_tcp? || pacote.is_udp?  
          if pacote.ip_header.nil?
            puts "Pacote capturado mas não tem cabeçalho IP."
            next
          end
</code></pre>

Na primeira condicional verificamos se o ip tem cabeçalho, caso não tenha, irá para o próximo pacote, e não irá imprimir aquele IP sem cabeçalho.
Importante contextualizar, que quando um IP não possui um cabeçalho, não apresente tanta utilidade de informações para serem computadas. Afinal, a partir do IP que conseguimos as informações básicas de tráfego.

### 2.3 Reconhecimento de ataque

 Começamos o reconhecimento de pacotes com o nosso 'HashContador' anteriormente criado, o mesmo será responsável por identificar se está acontecendo um ataque DOS no host.

<pre><code>
  ip_origem = pacote.ip_header.ip_saddr
  contagem_pacotes_ip[ip_origem] += 1  
</code></pre>

 Iremos criar uma variável para guardar o ip de origem, onde o pacote com o cabeçalho de ip e ip de origem serão guardados na variável 'ip_origem'.
 
 A partir disso, faremos a estrutura de contagem, colocado o ip de origem dentro ca contagem de pacotes, e a cada recebimento de pacotes com aquele ip de origem, iremos somar mais um para o contador.

 ### 2.4 Reconhecimento de pacotes

Passamos agora para a parte de reconhecimento de pacotes, onde iremos entender se aquele pacote é 'TCP' ou 'UDP' e foi fundamental capturarmos 'pacotes brutos' justamente para friltrar adequadamente qual tipo de pacote estamos recebendo no host.

<pre><code>
 if pacote.is_tcp?
            puts "Pacote TCP capturado!"
            puts "Origem: #{ip_origem}:#{pacote.tcp_sport}"
            puts "Destino: #{pacote.ip_header.ip_daddr}:#{pacote.tcp_dport}"
            unless pacote.tcp_header.body.empty?
              puts "Carga útil: #{pacote.tcp_header.body.inspect}"
            end
          elsif pacote.is_udp?
            puts "Pacote UDP capturado!"
            puts "Origem: #{ip_origem}:#{pacote.udp_sport}"
            puts "Destino: #{pacote.ip_header.ip_daddr}:#{pacote.udp_dport}"
            unless pacote.udp_header.body.empty?
              puts "Carga útil: #{pacote.udp_header.body.inspect}"
            end
          end
</code></pre>

 O cabeçalho de IP contem, os dados de origem, o destino e a carga útil do payload.

### 2.5 Condição de detecção de ataque

Aqui, o código verifica se o número de pacotes recebidos de um determinado IP de origem (ip_origem) é maior que 100. Este número pode ser ajustado conforme a necessidade e a tolerância do servidor ao tráfego.
A ideia é que, se um IP enviar mais de 100 pacotes em um curto período de tempo, isso pode ser um sinal de que está ocorrendo um ataque DDoS, já que esses ataques geralmente envolvem um grande volume de tráfego.

<pre><code>
if contagem_pacotes_ip[ip_origem] > 100:
</code></pre>

Caso em pouco tempo tenha grande quantidade de pacotes presentes, irá ser alertado no console uma mensagem.

<pre><code>
puts "Ataque DDoS potencial detectado do IP: #{ip_origem}!"
</code></pre>

### 2.6 Encerramento e condição de otimização

O código será encerrado em duas condições, caso ocorra um erro que venha a interromper a operação, e caso o usuário encerre com 'Contrl+C' fora isso, será de forma intermitente o monitoramento de pacotes.

Para fins de otimização, foi colocado para que tenha uma interrupção de um segundo no loop para que não venha a sobrecarregar o sistema.

<pre><code>
  end 
  sleep(1)  

    rescue Interrupt
    captura.stop
    puts "Monitoramento interrompido"
  end
end
</code></pre>

# 3.0 Como utilizar?

Primeiro passo para utilizar esse código, é instalar a gem 'packetfu'

<pre><code>
gem install packetfu
</code></pre>

### 3.1 Configurar o host de monitoramento

<pre><code>
iface: 'wlan0': A interface de rede que será monitorada. Verifique a interface correta no seu sistema usando um dos comandos a seguir:

    Linux: ip a

    Windows: ipconfig

    Mac: ifconfig
</code></pre>

### 3.2 Configurar o contador de identificação do DOS/DDOS

É fundamental configurar o tanto de pacotes o sistema irá precisar pra identificar se é um ataque DOS/DDOS ou não. Para isso, só mudar a condicional de monitoramento.

<pre><code>
   if contagem_pacotes_ip[ip_origem] > 100 # mudar de acordo com a necessidade  
            puts "Ataque DDoS potencial detectado do IP: #{ip_origem}!"
          end
</code></pre>

# 4.0 Utilização da ferramenta

Essa ferramenta pode ser utilizada em qualquer ambiente que possui host, precisamente pode ser utilizado em sistemas como: 

- Servidores Web, Ambientes de desenvolvimento, Centro de dados, Rede local(lan), Ambientes de produção, Roteadores e firewalls, Monitoramentos gerais etc.

# 5.0 Possíveis fraquezas da ferramenta

Existem possíveis situações que essa ferramenta de monitoramento venha a demonstrar eficiência reduzida, situações como:

### Dominios variados

É comum em ataques DDOS de larga escala, que venham acompanhados com constante mudanças de dominio, dificultando a identificação de um possível ataque. 

Exemplo: 

<pre><code>
Capturado IP: '192.168.0.1'
Capturado IP: '192.168.0.1'
Capturado IP: '192.168.0.1'
Capturado IP: '192.168.0.2'
Capturado IP: '192.168.0.2'
Capturado IP: '192.168.0.2'
Capturado IP: '192.168.0.3'
Capturado IP: '192.168.0.3'
Capturado IP: '192.168.0.3'
</code></pre>

A partir desse exemplo, observamos que caso venha a ter vários 'zumbis' mandando cargas de pacotes dom dominios varíaveis, há possibilidade da identificação ser menos precisa.

Outros possíveis problemas, encaixam-se no cenário:

### Dificuldade de Identificação:

  A constante mudança de IPs e domínios significa que, para um sistema de monitoramento que conta pacotes por IP, a detecção de um ataque se torna menos precisa. Por exemplo, se a ferramenta só está contando pacotes por IP, ela pode não perceber que todos esses IPs estão relacionados a um único ataque coordenado.

### Cargas Variáveis:

  Além dos endereços IP variáveis, as cargas úteis (ou payloads) também podem variar. Isso pode incluir tipos diferentes de pacotes, como TCP, UDP ou ICMP, tornando ainda mais complicado para o sistema de monitoramento classificar e identificar o ataque.



