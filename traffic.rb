require 'packetfu'

def monitoramento_servidor
  captura = PacketFu::Capture.new(:iface => 'enp3s0', :promisc => true)
  captura.start

  contagem_pacotes_ip = Hash.new(0)

  puts "Monitorando tráfego (Pressione Ctrl+C para interromper)"

  begin
    loop do
      pacote_raw = captura.next  
      if pacote_raw
        pacote = PacketFu::Packet.parse(pacote_raw)  

        if pacote.is_tcp? || pacote.is_udp?  

          if pacote.ip_header.nil?
            puts "Pacote capturado mas não tem cabeçalho IP."
            next
          end

          ip_origem = pacote.ip_header.ip_saddr
          contagem_pacotes_ip[ip_origem] += 1  

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

          if contagem_pacotes_ip[ip_origem] > 10  
            puts "Ataque DDoS potencial detectado do IP: #{ip_origem}!"
          end
        end
      end
      sleep(1)  
    end
  rescue Interrupt
    captura.stop
    puts "Monitoramento interrompido"
  end
end

monitoramento_servidor
