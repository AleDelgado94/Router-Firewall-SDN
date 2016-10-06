#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from netaddr import *
import ipaddr
import ast

def _leer_firewall(ruta_fichero):
        infile = open(ruta_fichero, 'r')
        num_lineas = len(infile.readlines())
        infile.seek(0)

        lineas = list( infile )

        lista = {}

        for i in range(num_lineas):
            principio_linea = True
            index = 0
            l = []

            for j in lineas[i].split(" "):
                if(principio_linea == True):
                    index = int(j)
                    if(int(j) not in lista.keys()):
                        lista[index] = []         
                else:
                    if(j == 'True\n' or j == 'False\n'):
                        l.append(ast.literal_eval(j))                
                        lista[index].append(l)
                    else:
                        if(j == 'None'):
                            l.append(ast.literal_eval(j))
                        else:
                            l.append(j)
                principio_linea = False

        return lista  


class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)
        # Creamos diccionario para la tabla de reenvío
        self.hash_routing = {}
        self.ARP_Cache = {}
        self.mayor = 0
        self.paquete = []


        self.interfaces = {1: ("192.168.0.1", "255.255.255.0", "00:00:00:00:01:01"), 2: ("192.168.1.1", "255.255.255.0", "00:00:00:00:01:02"), 3: ("192.168.2.1", "255.255.255.0", "00:00:00:00:01:03"), 4: ("192.168.3.1", "255.255.255.0", "00:00:00:00:01:04")}

        self.enrutamiento = {1: ("192.168.0.0", "255.255.255.0", "00:00:00:00:01:01", None), 2: ("192.168.1.0", "255.255.255.0", "00:00:00:00:01:02", None), 3: ("192.168.2.0", "255.255.255.0", "00:00:00:00:01:03", None), 4: ("192.168.3.0", "255.255.255.0", "00:00:00:00:01:04", None)}



        #self.firewall_in = {1: ([['192.168.1.2', None, None, None, True], [None, None, None, None, False]] )}

        #self.firewall_out = {1: ([[None, '192.168.1.2', None, None, True], [None, None, None, None, False]])}

        self.firewall_in = _leer_firewall("./firewall_entrada.txt")
        self.firewall_out = _leer_firewall("./firewall_salida.txt")

        #print self.firewall_in
        #print self.firewall_out



    def return_key(self, mac):
        for i, valor1 in self.interfaces.iteritems():
            if(valor1[2] == mac):
                return i

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
      msg = ev.msg
      datapath = msg.datapath
      ofproto = datapath.ofproto
      parser = datapath.ofproto_parser
      actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
      inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,actions=actions)]
      mod = parser.OFPFlowMod(datapath=datapath,priority=0, match=parser.OFPMatch(), instructions=inst)
      datapath.send_msg(mod)
      self.set_sw_config_for_ttl(datapath)


    #  Inserta una entrada a la tabla de flujo.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
				priority=priority, match=match,
				instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
				match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
		#print(mod)
		datapath.send_msg(mod)
          

    # Enviar un paquete construido en el controlador
    # hacia el switch
    def send_packet(self, datapath, port, pkt):
	    ofproto = datapath.ofproto
	    parser = datapath.ofproto_parser
	    pkt.serialize()
	    data = pkt.data
	    actions = [parser.OFPActionOutput(port=port)]
	    out = parser.OFPPacketOut(datapath=datapath,
			      buffer_id=ofproto.OFP_NO_BUFFER,
			      in_port=ofproto.OFPP_CONTROLLER,
			      actions=actions,
			      data=data)
	    datapath.send_msg(out)

    # Fijar la configuración del conmutador para que envía los paquetes con un TTL inválido al controlador.
    def set_sw_config_for_ttl(self, dp):
        packet_in_mask = (1 << dp.ofproto.OFPR_ACTION |
		          1 << dp.ofproto.OFPR_INVALID_TTL)
        port_status_mask = (1 << dp.ofproto.OFPPR_ADD |
			    1 << dp.ofproto.OFPPR_DELETE |
			    1 << dp.ofproto.OFPPR_MODIFY)
        flow_removed_mask = (1 << dp.ofproto.OFPRR_IDLE_TIMEOUT |
			      1 << dp.ofproto.OFPRR_HARD_TIMEOUT |
			      1 << dp.ofproto.OFPRR_DELETE)
        m = dp.ofproto_parser.OFPSetAsync(dp, [packet_in_mask, 0], [port_status_mask, 0],[flow_removed_mask, 0])
        dp.send_msg(m)


    def ARPREQUEST_packet(self, pkt ,datapath, port):
            ip = pkt.get_protocol(ipv4.ipv4)
            e = ethernet.ethernet(dst=mac.BROADCAST_STR , src=self.interfaces[port][2], ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(opcode=arp.ARP_REQUEST, src_mac=self.interfaces[port][2], src_ip=ip.src, dst_ip=ip.dst)
        
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)

            self.send_packet(datapath, port, p)

    



    def ARP_packet(self, pkt, datapath, in_port, msg):
        eth_msg = pkt.get_protocol(ethernet.ethernet)
        arp_msg= pkt.get_protocol(arp.arp)
        if(arp_msg == None):
            return
        if((arp_msg.dst_ip == self.interfaces[in_port][0]) and (arp_msg.opcode==arp.ARP_REQUEST)):
            e = ethernet.ethernet(dst=eth_msg.src, src=self.interfaces[in_port][2], ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(opcode=arp.ARP_REPLY, src_mac=self.interfaces[in_port][2], src_ip=arp_msg.dst_ip, dst_mac=eth_msg.src, dst_ip=arp_msg.src_ip)
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)
            self.send_packet(datapath, in_port, p)
        elif(arp_msg.opcode == arp.ARP_REPLY):

            for paquete in self.hash_routing[arp_msg.src_ip]:

                port_destino = self.ARP_Cache[arp_msg.dst_ip]               

                p = self.sacar_cola(arp_msg.src_ip)[0]
                datapath = p.datapath
            
                pkt_ = packet.Packet(p.data)
                
                ofp_parser = datapath.ofproto_parser
                ip = pkt_.get_protocol(ipv4.ipv4)
                self.ARP_Cache[ip.dst] = arp_msg.src_mac

                eth = pkt_.get_protocol(ethernet.ethernet)
                pkg_icmp = pkt_.get_protocol(icmp.icmp)
                pkt_tcp = pkt_.get_protocol(tcp.tcp)
                

                interfaz = self.return_key(eth.dst)  
  
                if(ip.proto == 1):
                    (match,actions) = self._firewall_(pkt_, ofp_parser, self.firewall_in , arp_msg.src_mac, self.interfaces[in_port][2], None, None ,in_port , in_port)
                    #print "La acción es: ", actions
                    prioridad = 1
                    if match==None:
                        prioridad = 0
                        match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)             
                            
                    if(len(actions) != 0):
                        (match, actions) = self._firewall_(pkt_, ofp_parser, self.firewall_out , arp_msg.src_mac, self.interfaces[interfaz][2],None, None, interfaz , in_port)
                        prioridad = 1
                        if match==None:
                            prioridad = 0
                            match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)
                    self.add_flow( datapath=datapath, priority=prioridad, match=match, actions=actions, buffer_id=p.buffer_id)

                elif(ip.proto == 6):
                    (match,actions) = self._firewall_(pkt_, ofp_parser, self.firewall_in , arp_msg.src_mac, self.interfaces[in_port][2], str(pkt_tcp.src_port), str(pkt_tcp.dst_port) ,in_port , in_port)
                    #print "La acción es: ", actions
                    prioridad = 1
                    if match==None:
                        prioridad = 0
                        match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)             
                            
                    if(len(actions) != 0):
                        (match, actions) = self._firewall_(pkt_, ofp_parser, self.firewall_out , arp_msg.src_mac, self.interfaces[interfaz][2], str(pkt_tcp.src_port), str(pkt_tcp.dst_port), interfaz , in_port)
                        prioridad = 1                        
                        if match==None:
                            prioridad = 0
                            match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)
                    self.add_flow( datapath=datapath, priority=prioridad, match=match, actions=actions, buffer_id=p.buffer_id)
                             

    def mayor_mask(self, list_coincidencias):
        mayor = 0
        maximo = 0
        num_unos = 0
        for i in list_coincidencias:
            for j in i[1]:
                if(j == '1'):
                    num_unos = num_unos + 1
            if (num_unos > maximo):
                mayor = i[0]
                maximo = num_unos
                
        return mayor

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp, src_ip, src_mac):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=src_mac))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src, src=src_ip, proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=pkt_icmp.data))
        self.send_packet(datapath, port, pkt)


    def insertar_cola(self, ip_addr, msg):
        if(ipaddr in self.hash_routing.keys()):
            self.hash_routing[ip_addr] = self.hash_routing[ip_addr]+[msg]
        else:
            self.hash_routing[ip_addr] = [msg]


    def sacar_cola(self, ip_addr):
        if ip_addr in self.hash_routing.keys():
            lista = self.hash_routing[ip_addr]
            del self.hash_routing[ip_addr]
            return lista
        else:
            return []
            



    #MODIFICACIÓN ADICIÓN DE FIREWALL AL ROUTER    

    def _firewall_(self, pkt, ofp_parser ,lista_reglas, eth_dst, eth_src, port_src_tcp, port_dst_tcp, in_port, port):

        procesando_regla = []

        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        #print pkt_icmp

        #print in_port

        #Si la interfaz dispone de firewalling
        if(in_port in lista_reglas.keys()):
            
            for entrada in lista_reglas[in_port]:

                #print "ENTRADA / SALIDA"
                procesando_regla.append(entrada)
            #print procesando_regla

            regla_actual = None
            for i in procesando_regla:    
                regla_actual = i
            
                #print "LA REGLA ACTUAL ES: "
                #print regla_actual

                if(regla_actual != None or len(regla_actual) != 0):
                    dir_origen = regla_actual[0]
                    dir_destino = regla_actual[1]
                    port_origen = regla_actual[2]
                    port_destino = regla_actual[3]
                    action = regla_actual[4] # True = accept | False = drop

    
                    match = None
                    if dir_origen == None and dir_destino == None:  
                        if(port_dst_tcp == None and port_src_tcp == None ):
                            #print "PUERTOS EN NONE"
                            match = None
                        elif(port_dst_tcp != None or port_src_tcp != None):
                            if(port_destino == None and port_dst_tcp != None):
                                match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_src=pkt_tcp.src_port, ip_proto=0x06)
                            elif(port_origen == None and port_src_tcp != None):
                                match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_dst=pkt_tcp.dst_port, ip_proto=0x06)
                        #match = None
                    elif dir_origen==None:
                        if(port_dst_tcp == None and port_src_tcp == None ):
                            match = ofp_parser.OFPMatch(ipv4_dst=dir_destino,eth_type=ether.ETH_TYPE_IP, in_port=in_port)
                        elif(port_dst_tcp != None or port_src_tcp != None):
                            if(port_destino == None and port_dst_tcp != None):
                                match = ofp_parser.OFPMatch(ipv4_dst=dir_destino, eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_src=pkt_tcp.src_port, ip_proto=0x06)
                            elif(port_origen == None and port_src_tcp != None):
                                match = ofp_parser.OFPMatch(ipv4_dst=dir_destino, eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_dst=pkt_tcp.dst_port, ip_proto=0x06)

                    elif dir_destino==None:
                        if(port_dst_tcp == None and port_src_tcp == None ):
                            match = ofp_parser.OFPMatch(ipv4_src=dir_origen,eth_type=ether.ETH_TYPE_IP, in_port=in_port)
                        elif(port_dst_tcp != None or port_src_tcp != None):
                            if(port_destino == None and port_dst_tcp != None):
                                match = ofp_parser.OFPMatch(ipv4_src=dir_origen, eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_src=pkt_tcp.src_port, ip_proto=0x06)
                            elif(port_origen == None and port_src_tcp != None):
                                match = ofp_parser.OFPMatch(ipv4_src=dir_origen, eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_dst=pkt_tcp.dst_port, ip_proto=0x06)
                    else:
                        if(port_origen == None and port_destino == None ):
                            match = ofp_parser.OFPMatch(ipv4_src=dir_origen,ipv4_dst=dir_destino,eth_type=ether.ETH_TYPE_IP, in_port=in_port)
                        elif(port_destino != None or port_origen != None):
                            if(port_destino == None and port_dst_tcp != None):
                                match = ofp_parser.OFPMatch(ipv4_src=dir_origen,ipv4_dst=dir_destino,eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_src=pkt_tcp.src_port, ip_proto=0x06)
                            elif(port_origen == None and port_src_tcp != None):
                                match = ofp_parser.OFPMatch(ipv4_src=dir_origen,ipv4_dst=dir_destino,eth_type=ether.ETH_TYPE_IP, in_port=in_port, tcp_dst=pkt_tcp.dst_port, ip_proto=0x06)

                    #print match


                    if(pkt_ip.proto == 6):

                        if((dir_origen == None or dir_origen == pkt_ip.src) and (dir_destino == None or dir_destino == pkt_ip.dst) and (port_origen == None or port_origen==port_src_tcp) and (port_destino == None or str(port_destino)==str(port_dst_tcp)) and (action != None and action == True)):
                            actions = [ofp_parser.OFPActionSetField(eth_dst=eth_dst), ofp_parser.OFPActionSetField(eth_src=eth_src), ofp_parser.OFPActionDecNwTtl(), ofp_parser.OFPActionOutput(port)]
                            return (match, actions)

                        elif((dir_origen == None or dir_origen == pkt_ip.src) and (dir_destino == None or dir_destino == pkt_ip.dst) and (port_origen == None or port_origen==port_src_tcp) and (port_destino == None or port_destino==port_dst_tcp) and (action != None and action == False)):
                            actions = []
                            return (match, actions)   
                    
                    elif(pkt_ip.proto == 1):

                        if((dir_origen == None or dir_origen == pkt_ip.src) and (dir_destino == None or dir_destino == pkt_ip.dst) and (port_destino == None) and (port_origen == None) and (action != None and action == True)):
                            actions = [ofp_parser.OFPActionSetField(eth_dst=eth_dst), ofp_parser.OFPActionSetField(eth_src=eth_src), ofp_parser.OFPActionDecNwTtl(), ofp_parser.OFPActionOutput(port)]
                            return (match, actions)

                        elif((dir_origen == None or dir_origen == pkt_ip.src) and (dir_destino == None or dir_destino == pkt_ip.dst) and (port_origen == None) and (port_destino == None) and (action != None and action == False)):
                            actions = []
                            return (match, actions)   

                regla_actual = None            

            procesando_regla = []

        else:
            match = None
            actions = [ofp_parser.OFPActionSetField(eth_dst=eth_dst), ofp_parser.OFPActionSetField(eth_src=eth_src), ofp_parser.OFPActionDecNwTtl(), ofp_parser.OFPActionOutput(port)]
            return (match,actions)






    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

        in_port = msg.match['in_port'] # Puerto de entrada.

        
       

        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        pkg_icmp = pkt.get_protocol(icmp.icmp)
        travesia = True

        
        if(eth.ethertype==ether.ETH_TYPE_ARP): #Si el paquete es del tipo ARP
            self.ARP_packet(pkt, datapath, in_port, msg)
        elif(eth.ethertype == ether.ETH_TYPE_IP): #Si el paquete es del tipo IP
            #print "IP Packet"
            ip = pkt.get_protocol(ipv4.ipv4)
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            
            if(ip.proto == 0x01 or ip.proto == 0x06): #Si el paquete es del tipo ICMP  

                for enruta in self.interfaces:
                    if(self.interfaces[enruta][0]==ip.dst): #Si el paquete icmp va dirigido al router
                        travesia = False
                        self._handle_icmp(datapath,in_port, eth, ip, pkg_icmp, ip.src, eth.src) #Mando el icmp al router
                if(travesia): #Si el paquete es de travesía
                    #print "El paquete es de travesía"

                    if msg.reason == ofproto.OFPR_INVALID_TTL:
                        actions = []
                        match = ofp_parser.OFPMatch(ipv4_dst=ip.dst,eth_type=ether.ETH_TYPE_IP)
                        self.add_flow(datapath, 0, match, actions, msg.buffer_id)
                        return
            
                    #Comprobamos la tabla de enrutamiento

                    multiples_entradas = []
                    for enruta in self.enrutamiento:
                        if (ipaddr.IPAddress(ip.dst) in ipaddr.IPNetwork(self.enrutamiento[enruta][0]+"/"+self.enrutamiento[enruta][1])):
                            multiples_entradas.append([enruta, IPAddress(self.enrutamiento[enruta][1]).bin])
                    self.mayor = self.mayor_mask(multiples_entradas)


                    if ip.src not in self.ARP_Cache: 
                        self.ARP_Cache[ip.src] = eth.src             
                    if ip.dst not in self.ARP_Cache: #La ip de destino no se encuentra en la Cache ARP

                        self.insertar_cola(ip.dst, msg)
                        self.ARPREQUEST_packet(pkt, datapath, self.mayor)  
                        

                    elif ip.dst in self.ARP_Cache: #La dirección de destino se encuentra en la estructura ARP_CACHE. -> Añadimos a la tabla de flujo
                        
                        ## SI ES UN PAQUETE DE TIPO ICMP
                        if(ip.proto == 0x01):
                            (match, actions) = self._firewall_(pkt, ofp_parser, self.firewall_out , self.ARP_Cache[ip.dst], self.interfaces[self.mayor][2], None, None, in_port , self.mayor)
                            prioridad = 1
                            if match==None:
                                prioridad = 0
                                match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)                        
                                              

                            if(len(actions) != 0):
                                (match, actions) = self._firewall_(pkt, ofp_parser, self.firewall_in ,self.ARP_Cache[ip.dst], self.interfaces[self.mayor][2], None, None ,self.mayor , self.mayor)
                                prioridad = 1
                                if match==None:
                                    prioridad = 0
                                    match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP) 

                        ## SI NO, SE TRATA DE UN PAQUETE TCP
                        elif (ip.proto == 6):

                            (match, actions) = self._firewall_(pkt, ofp_parser, self.firewall_out , self.ARP_Cache[ip.dst], self.interfaces[self.mayor][2], str(pkt_tcp.src_port), str(pkt_tcp.dst_port), in_port , self.mayor)

                            prioridad = 1
                            if match==None:
                                prioridad = 0
                                match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)                        
        
                        
                            if(len(actions) != 0):
                                prioridad = 1
                                (match, actions) = self._firewall_(pkt, ofp_parser, self.firewall_in ,self.ARP_Cache[ip.dst], self.interfaces[self.mayor][2], str(pkt_tcp.src_port), str(pkt_tcp.dst_port), self.mayor , self.mayor)
                                
                                if match==None:
                                    prioridad = 0
                                    match = ofp_parser.OFPMatch(ipv4_dst=ip.dst, eth_type=ether.ETH_TYPE_IP)
                  


                        self.add_flow( datapath=datapath, priority=prioridad, match=match, actions=actions, buffer_id=msg.buffer_id)

