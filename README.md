# Monitoramento-ddos

# 1.0 Explicação do código

 Foi criado com o intuito de monitorar o tráfego de entrada um servidor a partir dos pacotes enviados para o mesmo, atráves de um Ip. O monitoramento consiste na utilização da linguagem ruby com a gem 'packetfu' com o intuito de ánalisar de aquele IP está com possíveis inteções de DDOS.
 Para a realização desse código, foi imprescendível a utilização da gem 'packetfu' ótima para monitoramento de sockets, disponível como gem do ruby.

# 1.1 Gem

'Packetfu' é uma biblioteca/gem disponível no Ruby para análises de trafego, assim como a biblioteca sockets, ela é possível identificar atráves de um conjunto de ferrametas identificar um conjunto de comportamentos que por padrão são identificados em um ataque DOS ou DDOS, que consiste na sobrecarega de um servidor atráves no envio de pacotes. 

Pensando nisso, utilizei a biblioteca 'packetfu' por ser a que melhor se adapta nesse contexto de análise de tráfego.

# 2.0 Como funciona?

