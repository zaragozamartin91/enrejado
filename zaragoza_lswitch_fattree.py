from pox.core import core 
import pox.log.color
import pox.log
import pox.openflow.discovery
import pox.openflow.spanning_tree
from pox.lib.recoco import Timer
from collections import defaultdict
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time
from pox.lib.util import dpid_to_str

block_ports = set() 
log = core.getLogger()

# diccionario de componentes adyacentes
# The defaultdict will simply create any non-existing items that you try to access. To create such a "default" item, it calls the function object that you pass in the constructor 
adj = defaultdict(lambda:defaultdict(lambda:[]))
# set de switch_ids
switch_ids = set()
# diccionario switch_id -> Switch (ver clase mas abajo)
switches = dict()

# Determinan / ajustan un tiempo de bloqueo de floods. 
# Este tiempo se incrementara cada vez que se detecte un nuevo switch y un nuevo enlace
FLOOD_DELAY_INCREMENT = 0
_flood_delay = FLOOD_DELAY_INCREMENT

# algunas constantes y numeros magicos utiles para debuguear
DHCP_PORT = 67
TCP_nw_proto = pkt.ipv4.TCP_PROTOCOL # 6
UDP_nw_proto = pkt.ipv4.UDP_PROTOCOL # 17
ICMP_nw_proto = pkt.ipv4.ICMP_PROTOCOL # 1

IP_dl_type = pkt.ethernet.IP_TYPE # 2048

# valor por defecto de duracion de un flujo instalado en un switch
FLOW_INSTALL_DURATION = 10
# Cantidad de paquetes UDP hacia un mismo destino que determinan la instalacion del FIREWALL
UDP_FIREWALL_THRESHOLD = 100
# Determina si se debe tener en cuenta el puerto destino udp para activar el FIREWALL
USE_UDP_PORT_FOR_FIREWALL = False


def find_switch_path(curr_switch_id , end_switch_id , found_paths = [], curr_path = []):
  print('curr_switch_id: ' , curr_switch_id , ' ; end_switch_id: ' , end_switch_id , ' ; curr_path: ' , curr_path)
  path_copy = list(curr_path) # copio la lista del path actual
  path_copy.append(curr_switch_id) # agrego el switch actual a la lista
  # si el switch actual es igual al que busco -> encontre un camino valido
  if curr_switch_id == end_switch_id: 
    found_paths.append(path_copy)
    print('Path found: ' , path_copy)
    return True
  any_path_found = False
  for adj_sw_id in adj[curr_switch_id]:
    # evito visitar nuevamente los mismos switches
    if adj_sw_id not in curr_path:
      path_found = find_switch_path(adj_sw_id , end_switch_id , found_paths , path_copy)
      any_path_found = any_path_found or path_found
  return any_path_found

# DEFINO FUNCIONES Y LISTENERS DE ESTADISTICAS DE SWITCHES PARA EVENTUALMENTE ARMAR EL FIREWALL -------------
  

"""
EJEMPLO DE FUNCION QUE SOLICITA DATOS ESTADISTICOS PARA UN FLUJO ESPECIFICO
def request_udp_flow_stats(switch_id , udp_dst_ip , udp_dst_port):
  sw = switches[switch_id]
  con = sw.connection
  req_body = of.ofp_flow_stats_request()
  req_match = None
  if USE_UDP_PORT_FOR_FIREWALL: 
    req_match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto, tp_dst=udp_dst_port)
  else: 
    req_match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto)
  req_match.set_nw_dst(udp_dst_ip,32) # Sets the IP source address and the number of bits to match
  req_body.match = req_match
  msg = of.ofp_stats_request(body=req_body)
  con.send(msg)
"""

def request_flow_stats(switch_id):
  sw = switches[switch_id]
  con = sw.connection
  msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
  con.send(msg)

# Funciones para determinar tipo de flujo / estadistica a partir de un objeto ofp_match
def is_udp(match):
  return match.dl_type == pkt.ethernet.IP_TYPE and match.nw_proto == UDP_nw_proto
  
def is_tcp(match):
  return match.dl_type == pkt.ethernet.IP_TYPE and match.nw_proto == TCP_nw_proto
  
def is_icmp(match):
  return match.dl_type == pkt.ethernet.IP_TYPE and match.nw_proto == ICMP_nw_proto
  
  
def handle_flow_stats (event):
  """ Listener que muestra datos estadisticos de un switch. Captura eventos FlowStatsReceived """
  switch_id = event.connection.dpid
  all_stats = { 
    "tcp":{"packet_count":0 , "byte_count":0} , 
    "udp":{"packet_count":0 , "byte_count":0} , 
    "icmp":{"packet_count":0 , "byte_count":0} }
  for f in event.stats:
    if is_udp(f.match): 
      all_stats["udp"]["packet_count"] += f.packet_count
      all_stats["udp"]["byte_count"] += f.byte_count
    
    if is_tcp(f.match):
      all_stats["tcp"]["packet_count"] += f.packet_count
      all_stats["tcp"]["byte_count"] += f.byte_count
      
    if is_icmp(f.match):
      all_stats["icmp"]["packet_count"] += f.packet_count
      all_stats["icmp"]["byte_count"] += f.byte_count
  log.info("SWITCH_%s stats: %s" , switch_id , all_stats)
  
def handle_flow_removed(event):
  """ Listener que maneja eliminaciones de flujos en switches. Escucha eventos tipo FlowRemoved """
  switch_id = event.connection.dpid
  log.info('SWITCH_%s: FLUJO REMOVIDO!' , switch_id)
  match = event.ofp.match

  if is_udp(match): 
    dst_ip = match.get_nw_dst() # Tupla IP , bits_mascara. Ejemplo: (IPAddr('10.0.0.2'), 32)
    packet_count = event.ofp.packet_count
    log.info('SWITCH_%s: FLUJO REMOVIDO ES UDP PARA IP %s' , switch_id, dst_ip)
    if packet_count > UDP_FIREWALL_THRESHOLD: 
      blackhole_udp_packets(switch_id , FLOW_INSTALL_DURATION , dst_ip)

def blackhole_udp_packets (switch_id , duration , udp_dst_ip , udp_dst_port=None):
  """ Instala un flujo de dopeo de paquetes UDP para un destino determinado """
  # NOTA: ESTA FUNCION INSTALA UN FIREWALL TIPO BLACKHOLE EN UN SOLO SWITCH... SE DEBE CONSIDERAR SI ACASO EL FIREWALL
  # DEBE INSTALARSE EN TODOS LOS SWITCHES...
  log.info('SWITCH_%s: REALIZANDO BLACKHOLE DE PAQUETES HACIA %s ' , switch_id , udp_dst_ip[0] )
  msg = of.ofp_flow_mod()
  if USE_UDP_PORT_FOR_FIREWALL:
    msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto, tp_dst=udp_dst_port)
  else:
    msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto)
  msg.match.set_nw_dst( str(udp_dst_ip[0]) , udp_dst_ip[1])
  msg.idle_timeout = duration
  msg.hard_timeout = duration
  # msg.buffer_id = packet_in.buffer_id
  switches[switch_id].connection.send(msg)

# CONTROLLER CLASS ----------------------------------------------------------------------------------------
  
class ZgnLswitchFattree:
  def __init__ (self):  
    # Listen to dependencies
    def startup ():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)        
      # Listen for flow stats
      core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
      core.openflow.addListenerByName("FlowRemoved", handle_flow_removed)
      log.debug("ZgnLswitchFattree ESTA LISTO")
      
    core.call_when_ready(startup, ('openflow','openflow_discovery'))

  def _handle_ConnectionUp (self, event):
    """ Listener de NUEVO SWITCH conectado """
    global _flood_delay
    _flood_delay = _flood_delay + FLOOD_DELAY_INCREMENT
    log.debug('NUEVO SWITCH DETECTADO _flood_delay: %d SEGUNDOS' % _flood_delay)
    # Creo un nuevo switch
    Switch(event.connection , event.dpid)
    
  def _handle_LinkEvent (self, event):
    """ Listener de NUEVO ENLACE """
    global _flood_delay
    _flood_delay = _flood_delay + FLOOD_DELAY_INCREMENT
    log.debug('NUEVO ENLACE DETECTADO _flood_delay: %d SEGUNDOS' % _flood_delay)
    self._adjust_adjacency()
    
  def _adjust_adjacency(self):
    """ Ajusta la ADYACENCIA entre componentes conectados """
    log.debug('AJUSTANDO ADYACENCIA')
    adj.clear()
    switch_ids.clear()
    # por cada enlace nuevo, se ajustan adj y switch_ids
    for l in core.openflow_discovery.adjacency:
      adj[l.dpid1][l.dpid2].append(l)
      switch_ids.add(l.dpid1)
      switch_ids.add(l.dpid2)

# Switch CLASS ----------------------------------------------------------------------------------------

class Switch:
  def __init__ (self , connection , dpid):
    # Guarda la conexion con el switch
    self.connection = connection
    # guardo el id del switch y un sinonimo del mismo
    self.switch_id = dpid
    self.dpid = dpid
    log.info("SWITCH %s CONECTADO" % self.switch_id)
    # TABLA Mac -> puerto_salida_switch
    self.mac_to_port = {}
    # Agrego listeners de conexion (como PacketIn)
    self.connection.addListeners(self)
    switches[dpid] = self
    
    
  def _handle_PacketIn (self, event):
    packet_in = event.ofp # objeto EVENTO de tipo PACKET_IN.
    packet = event.parsed
    
    src_mac = packet.src # MAC origen del paquete
    dst_mac = packet.dst # MAC destino del paquete
    in_port = packet_in.in_port # puerto de switch por donde ingreso el paquete
    
    def install_flow(out_port , duration = FLOW_INSTALL_DURATION):
      """ Instala un flujo en el switch del tipo MAC_ORIGEN@PUERTO_ENTRADA -> MAC_DESTINO@PUERTO_SALIDA """
      log.info("SWITCH_%s: FLUJO INSTALADO %s@PUERTO_%i -> %s@PUERTO_%i" % (self.switch_id,src_mac, in_port, dst_mac, out_port))
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, in_port)
      msg.idle_timeout = duration
      msg.hard_timeout = duration
      msg.actions.append(of.ofp_action_output(port = out_port))
      msg.data = packet_in
      # esta linea es mucho muy importante dado que indica al switch que debe notificar al controlador cuando un flujo haya
      # sido dado de baja. Ver funcion handle_flow_removed
      msg.flags = of.OFPFF_SEND_FLOW_REM
      self.connection.send(msg)
      
    def drop (duration = None):
      """
      Dropea el paquete y opcionalmente instala un flujo en el switch para que siga dropeando paquetes de este tipo.
      NOTA: PODRIA USARSE PARA EL FIREWALL
      """
      if duration is not None:
        if not isinstance(duration, tuple): duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
      elif packet_in.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = packet_in.buffer_id
        msg.in_port = in_port
        self.connection.send(msg)
        
    def flood ():
      """ Hace un flood de los paquetes UNICAMENTE por los puertos habilitados por SPT """
      msg = of.ofp_packet_out() # se crea el mensaje de flood
      time_diff = time.time() - self.connection.connect_time
      flood_ok = time_diff >= _flood_delay
      if flood_ok:
        # Realizar flood solo despues de que venza el tiempo de prevencion de flood
        log.debug("SWITCH_%i: FLOOD %s -> %s", self.switch_id,src_mac,dst_mac)
        # Hacemos flood por todos los puertos excepto los bloqueados por el SPT
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        log.debug("ESPERANDO FLOOD DE SWITCH %s , RESTAN %d SEGUNDOS" % (self.switch_id, int(_flood_delay - time_diff)))
      msg.data = packet_in
      msg.in_port = in_port
      self.connection.send(msg)

    def handle_all():
      """ Maneja los paquetes de forma generica """
      # TODO : MODIFICAR ESTE COMPORTAMIENTO PARA SOPORTAR ECMP
      # si el puerto de salida se encuentra en la tabla de MACs entonces instalo un flujo en el switch
      if dst_mac in self.mac_to_port:
        out_port = self.mac_to_port[dst_mac]
        install_flow(out_port)
      else:
        flood()
    
    eth_getNameForType = pkt.ETHERNET.ethernet.getNameForType(packet.type)
    # Parseo tempranamente los tipos de datos conocidos 
    pkt_is_ipv6 = eth_getNameForType == 'IPV6'
    icmp_pkt = packet.find('icmp')
    tcp_pkt = packet.find('tcp')
    udp_pkt = packet.find('udp')
    pkt_is_arp = packet.type == packet.ARP_TYPE
    ip_pkt = packet.find('ipv4')
    
    def handle_dhcp():
      """ Maneja paquetes DHCP ... Pensar si acaso deberian dropearse... """
      dstip = ip_pkt.dstip
      log.debug('MANEJANDO PAQUETE DHCP HACIA IP %s' % str(dstip) )
      handle_all()
    
    def handle_udp():
      """ Maneja paquetes UDP. Debe detectar ataques udp e instalar un firewall temporal en el switch """
      dstip = ip_pkt.dstip
      dstport = udp_pkt.dstport
      if dstport == DHCP_PORT : return handle_dhcp()
      log.debug('MANEJANDO PAQUETE UDP HACIA IP %s:%d' % (str(dstip),dstport) )
      handle_all()
      
    
    # LOS PAQUETES DESCONOCIDOS SON DROPEADOS. POR AHORA IGNORAMOS LOS PAQUETES IPV6
    unknown_pkt = pkt_is_ipv6 or ( icmp_pkt is None and tcp_pkt is None and udp_pkt is None and not pkt_is_arp )
    if unknown_pkt:
      #log.debug('PAQUETE DESCONOCIDO DETECTADO')
      drop()
      return
    
    # Obtengo el nombre 'imprimible' del paquete
    pkt_type_name = ''
    if icmp_pkt : pkt_type_name = 'ICMP'
    if tcp_pkt : pkt_type_name = 'TCP'
    if udp_pkt : pkt_type_name = 'UDP'
    if pkt_is_arp : pkt_type_name = 'ARP'
    log.debug('SWITCH_%s#PORT_%d -> PAQUETE TIPO %s::%s MAC_ORIGEN: %s MAC_DESTINO: %s' % 
      (self.switch_id,in_port,eth_getNameForType,pkt_type_name,src_mac,dst_mac))
    
    # guardo la asociacion mac_origen -> puerto_entrada
    self.mac_to_port[src_mac] = in_port
    
    # si el paquete es udp lo manejo como tal
    if udp_pkt and ip_pkt: return handle_udp()
 
    handle_all() 
      
    
# launch ----------------------------------------------------------------------------------------------------------------------


def launch ():
  pox.log.color.launch()
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")  
  
  pox.openflow.discovery.launch()
  
  # no_flood: If True, we set ports down when a switch connects
  # hold_down: If True, don't allow turning off flood bits until a complete discovery cycle should have completed (mostly makes sense with _noflood_by_default).
  pox.openflow.spanning_tree.launch(no_flood = True, hold_down = True)
  
  
  core.registerNew(ZgnLswitchFattree)
  
  # Estas lineas de abajo exponen las variables adj y switch_ids al modulo interactivo de pox 'PY'
  core.Interactive.variables['adj'] = adj
  core.Interactive.variables['switch_ids'] = switch_ids
  core.Interactive.variables['switches'] = switches
  core.Interactive.variables['stats'] = request_flow_stats
  
  # AVERIGUAR PARA QUE SIRVE WaitingPath EN l2_multi
  #timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  #Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)


  
pox.openflow.spanning_tree.launch()
