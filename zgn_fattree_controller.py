from pox.lib.addresses import IPAddr, EthAddr
from pox.core import core 
import pox.log.color
import pox.log
import pox.openflow.discovery
import pox.openflow.spanning_tree
import host_tracker
from pox.lib.recoco import Timer
from collections import defaultdict
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time
from pox.lib.util import dpid_to_str


block_ports = set() 
log = core.getLogger()

# NOTA: CADA VEZ QUE HABLO DE SWITCH_ID ME ESTOY REFIRIENDO AL dpid DE LAS CONEXIONES DE LOS SWITCHES


# diccionario de switches adyacentes. Contiene datos de tipo Link. 
# Ejemplo de entrada: Link(dpid1=1,port1=1, dpid2=2,port2=1). 
# Esta entrada quiere decir: el switch 1 esta conectado con el switch 2 por el puerto 1 del switch 1
adj = defaultdict(lambda:defaultdict(lambda:None))
# set de SWITCH_IDs
switch_ids = set()
# diccionario SWITCH_ID -> Switch (ver clase mas abajo)
switches = dict()
# diccionario de tuplas de tipo: HOST_MAC_STRING -> (SWITCH_ID , PUERTO_SWITCH)
hosts = dict()
# set de paths de switches tomados
taken_paths = set()
# Diccionario de caminos de flujos existentes indexado por flow_key (ver funcion build_flow_key)
current_paths = dict()
# Diccionario de cantidad de veces que un camino esta siendo usado indexado por el array string del camino
current_paths_load = defaultdict(lambda:0)

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
# valor por defecto de duracion del firewall en segundos
FIREWALL_DURATION = 10
# Cantidad de paquetes UDP hacia un mismo destino que determinan la instalacion del FIREWALL
UDP_FIREWALL_THRESHOLD = 100
# Determina si se debe tener en cuenta el puerto destino udp para activar el FIREWALL
USE_UDP_PORT_FOR_FIREWALL = False
# Flag que determina el tipo de manejo ip a hacer
HANDLE_IP_COMPLEX = True

def set_udp_firewall_thresh(value = 100):
  """ Establece el valor limite de cantidad de paquetes UDP por flujo para la activacion del firewall """
  global UDP_FIREWALL_THRESHOLD
  UDP_FIREWALL_THRESHOLD = value

def request_all_flow_stats():
  """ Solicita datos de estadisticas a todos los switches """
  for s_id in switch_ids:
    request_flow_stats(s_id)

def find_switch_path(curr_switch_id , end_switch_id , found_paths = [], curr_path = []):
  """ Esta funcion encuentra todos los caminos posibles entre dos switches. Los caminos son poblados como un arreglo de arreglos 
  en el parametro found_paths , por lo cual para obtener los caminos disponibles se debe pasar un arreglo vacio como parametro found_paths.
  curr_switch_id: SWITCH_ID inicial
  end_switch_id: SWITCH_ID final. """
  #print('curr_switch_id: ' , curr_switch_id , ' ; end_switch_id: ' , end_switch_id , ' ; curr_path: ' , curr_path)
  path_copy = list(curr_path) # copio la lista del path actual
  path_copy.append(curr_switch_id) # agrego el switch actual a la lista
  # si el switch actual es igual al que busco -> encontre un camino valido
  if curr_switch_id == end_switch_id: 
    found_paths.append(path_copy)
    #print('Path found: ' , path_copy)
    return True
  any_path_found = False
  for adj_sw_id in adj[curr_switch_id]:
    # evito visitar nuevamente los mismos switches
    if adj_sw_id not in curr_path:
      path_found = find_switch_path(adj_sw_id , end_switch_id , found_paths , path_copy)
      any_path_found = any_path_found or path_found
  return any_path_found
  

def find_non_taken_path(curr_switch_id , end_switch_id):
  """ Obtiene el primer path de switches no tomado. 
  El retorno es un arreglo de SWITCH_IDs , ej: [1,2,4]. Si no existe ningun path disponible, retorna None """
  found_paths = []
  find_switch_path(curr_switch_id , end_switch_id , found_paths)
  #log.info("find_non_taken_path: found_paths = %s" , str(found_paths))
  shortest_path = None
  for fp in found_paths:
    if str(fp) not in taken_paths: 
      if shortest_path is None: shortest_path = fp
      if len(fp) < len(shortest_path): shortest_path = fp
  return shortest_path
  
def find_any_path(curr_switch_id , end_switch_id):
  """ Obtiene cualquier path de un switch origen a un destino. Si no hay ningun path retorna None. 
  TODO: mejorar este metodo para que retorne paths ALEATORIOS """
  found_paths = []
  find_switch_path(curr_switch_id , end_switch_id , found_paths)
  #log.info("find_any_path: found_paths = %s" , str(found_paths))
  shortest_load = 99999999
  shortest_path = None
  for fp in found_paths:
    fp_str = str(fp)
    path_load = current_paths_load[fp_str]
    if shortest_path is None: shortest_path = fp
    # si encuentro un path mas corto que el actual Y QUE ademas esta en desuso, entonces lo priorizo
    if len(fp) < len(shortest_path) and path_load <= shortest_load: 
      shortest_path = fp
      shortest_load = path_load
  return shortest_path
  
  

# DEFINO FUNCIONES Y LISTENERS DE ESTADISTICAS DE SWITCHES PARA EVENTUALMENTE ARMAR EL FIREWALL -------------
  


# LAS LINEAS DE ABAJO SON PARA UNA SOLUCION ALTERNATIVA DEL FIREWALL CON SOLICITUD DE ESTADISTICAS PERIODICAS  
#def request_udp_flow_stats(switch_id , udp_dst_ip , udp_dst_port = None):
#  """FUNCION QUE SOLICITA DATOS ESTADISTICOS PARA UN FLUJO ESPECIFICO UDP ESPECIFICO"""
#  log.info('SOLICITANDO FLOW STATS UDP DE SWITCH %s CON IP DESTINO %s' , switch_id , udp_dst_ip)
#  sw = switches[switch_id]
#  con = sw.connection
#  req_body = of.ofp_flow_stats_request()
#  req_match = None
#  if USE_UDP_PORT_FOR_FIREWALL: 
#    req_match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto, tp_dst=udp_dst_port)
#  else: 
#    req_match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto)
#  req_match.set_nw_dst(udp_dst_ip,32) # Sets the IP source address and the number of bits to match
#  req_match.pepe = 1 # pruebo agregar un elemento custom al match
#  req_body.match = req_match
#  msg = of.ofp_stats_request(body=req_body)
#  con.send(msg)


def request_flow_stats(switch_id):
  """ Solicita estadisticas de flujo de un switch. """
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

# LAS LINEAS DE ABAJO SON PARA UNA SOLUCION ALTERNATIVA DEL FIREWALL CON SOLICITUD DE ESTADISTICAS PERIODICAS  
#def handle_udp_flow_stats (event):
#  log.info("MANEJANDO STATS UDP")
#  switch_id = event.connection.dpid
#  packet_count = 0
#  dst_ip = None
#  for f in event.stats:
#    if hasattr(f.match, 'pepe'): log.info("ATRIBUTO PEPE EXISTE!")
#    if is_udp(f.match): 
#      packet_count += f.packet_count
#      dst_ip = f.match.get_nw_dst()
#      log.info("SWITCH_%s : handle_udp_flow_stats : dst_ip = %s" , switch_id , dst_ip)
#  log.info("SWITCH_%s : handle_udp_flow_stats : packet_count = %s" , switch_id , packet_count)
#  if packet_count > UDP_FIREWALL_THRESHOLD:
#    blackhole_udp_packets(switch_id , FIREWALL_DURATION , dst_ip)
#  else:
#    remove_udp_blackhole(switch_id , dst_ip)

# LAS LINEAS DE ABAJO SON PARA UNA SOLUCION ALTERNATIVA DEL FIREWALL CON SOLICITUD DE ESTADISTICAS PERIODICAS
#def remove_udp_blackhole(switch_id , udp_dst_ip):
#  """ Funcion para dar de baja un firewall """
#  log.info('SWITCH_%s: REMOVIENDO FIREWALL DE PAQUETES CON DESTINO %s ' , switch_id , udp_dst_ip[0] )
#  msg = of.ofp_flow_mod()
#  if USE_UDP_PORT_FOR_FIREWALL:
#    msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto, tp_dst=udp_dst_port)
#  else:
#    msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto)
#  msg.match.set_nw_dst( str(udp_dst_ip[0]) , udp_dst_ip[1])
#  msg.command = of.OFPFC_DELETE
#  switches[switch_id].connection.send(msg)


def handle_flow_removed(event):
  """ Listener que maneja eliminaciones de flujos en switches. Escucha eventos tipo FlowRemoved """
  switch_id = event.connection.dpid
  match = event.ofp.match
  packet_count = event.ofp.packet_count

  if is_udp(match): 
    dst_ip = match.get_nw_dst() # Tupla IP , bits_mascara. Ejemplo: (IPAddr('10.0.0.2'), 32)
    log.info('SWITCH_%s: FLUJO REMOVIDO DE TIPO UDP CON DESTINO IP %s . packet_count: %s' , switch_id, str(dst_ip[0]) , packet_count)
    if packet_count > UDP_FIREWALL_THRESHOLD:
      # Si la cantidad de paquetes UDP supera el THRESHOLD establecido -> instalo un blackhole firewall
      blackhole_udp_packets(switch_id , FIREWALL_DURATION , dst_ip)
    else:
      # Si la cantidad de paquetes UDP para un destino baja luego de un tiempo, entonces se lo quita del blacklist de destinos bloqueados
      str_dst_ip = str(dst_ip[0])
      switch = switches[switch_id]
      switch.remove_firewall_ip(str_dst_ip)

  elif is_icmp(match):
    log.debug('SWITCH_%s: FLUJO REMOVIDO DE TIPO ICMP . packet_count: %s' , switch_id, packet_count)
  elif is_tcp(match):
    dst_ip = match.get_nw_dst() # Tupla IP , bits_mascara. Ejemplo: (IPAddr('10.0.0.2'), 32)
    log.debug('SWITCH_%s: FLUJO REMOVIDO DE TIPO TCP CON DESTINO IP %s . packet_count: %s' , switch_id, dst_ip , packet_count)
  else:
    log.debug('SWITCH_%s: FLUJO REMOVIDO packet_count: %s' , switch_id , packet_count)
      
def blackhole_udp_packets (switch_id , duration , udp_dst_ip , udp_dst_port=None):
  """ Instala un flujo de dopeo de paquetes UDP para un destino determinado """
  # NOTA: ESTA FUNCION INSTALA UN FIREWALL TIPO BLACKHOLE EN UN SOLO SWITCH... SE DEBE CONSIDERAR SI ACASO EL FIREWALL DEBE INSTALARSE EN TODOS LOS SWITCHES AL MISMO TIEMPO...
  str_dst_ip = str(udp_dst_ip[0])
  switch = switches[switch_id]
  switch.add_firewall_ip(str_dst_ip)
  log.info('SWITCH_%s: INSTALANDO FIREWALL DE PAQUETES CON DESTINO %s ' , switch_id , str_dst_ip )
  msg = of.ofp_flow_mod()
  if USE_UDP_PORT_FOR_FIREWALL:
    msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto, tp_dst=udp_dst_port)
  else:
    msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto)
  msg.match.set_nw_dst( str_dst_ip , udp_dst_ip[1])
  msg.idle_timeout = duration
  msg.hard_timeout = duration
  msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Enviar el paquete a la NADA
  msg.flags = of.OFPFF_SEND_FLOW_REM # Generar evento FlowRemoved luego de que el flujo sea removido
  switches[switch_id].connection.send(msg)
  # LAS LINEAS DE ABAJO SON PARA UNA SOLUCION ALTERNATIVA DEL FIREWALL CON SOLICITUD DE ESTADISTICAS PERIODICAS
  #udp_flow_stats_lambda = lambda: request_udp_flow_stats(switch_id ,str(udp_dst_ip[0]) )
  #timeout = int( FIREWALL_DURATION / 2 )
  #Timer(timeout, udp_flow_stats_lambda)
  


# POTENCIAL FUNCION PARA INSTALAR UN FWALL EN TODOS LOS SWITCHES
#def blackhole_udp_packets_on_all_switches(duration , udp_dst_ip , udp_dst_port=None):
#  for k in switches.keys():
#    blackhole_udp_packets (k , duration , udp_dst_ip , udp_dst_port)

def set_ip_complex(enabled = True):
  global HANDLE_IP_COMPLEX
  HANDLE_IP_COMPLEX = enabled

def handle_host_tracker_HostEvent (event):
  """ Listener de eventos tipo HOST NUEVO CONECTADO """
  
  host_mac = str(event.entry.macaddr)
  switch_id = event.entry.dpid
  switch_port = event.entry.port
  
  # Supuesto codigo para obtener la ip de un host inmediatamente... no funciona
  #ipaddr_keys = event.entry.ipAddrs.keys()
  #ip = None
  #if len(ipaddr_keys) > 0 :
  #  ip = ipaddr_keys[0].toStr()
  
  if host_mac not in hosts:
    hosts[host_mac] = { "switch_id" : switch_id , "switch_port" : switch_port }
    if switch_id in switches:
      log.info('NUEVO HOST %s CON SWITCH_%s@PORT_%s' , host_mac , switch_id , switch_port)
    else:
      log.warn("Missing switch")

  # TODO: SOLO PARA PRUEBAS... ELIMINAR
  # if len(hosts) == 11: set_ip_complex(True)
      
def get_host_tracker_entries():
  """ Obtiene las entradas de hosts conocidas por el modulo host_tracker """
  return core.host_tracker.entryByMAC

def host_exists(host_mac):
  """ Retorna true si un host (NO SWITCH) existe """
  host_mac_str = str(host_mac)
  return host_mac_str in hosts
      
def get_host_ip(host_mac):
  """ Funcion que retorna la IP de un host (NO SWITCH) a partir de una direccion MAC.
  Si el controlador no conoce la ip del host, entonces retorna None."""
  host_mac_str = str(host_mac)
  if not host_exists(host_mac_str): return None
  
  host_tracker_entries = get_host_tracker_entries()
  hm = EthAddr(host_mac_str)
  if hm not in host_tracker_entries: return None
  
  ht_entry = host_tracker_entries[hm]
  ip_addrs = ht_entry.ipAddrs
  if len(ip_addrs.keys()) == 0: return None
  return ip_addrs.keys()[0].toStr()
    
    
def get_host_mac(host_ip):
  """ Obtiene la direccion mac de un host (NO SWITCH) a partir de su IP.
  Retorna None si el controlador no conoce al host o si la ip del host aun no es conocida."""
  host_ip_str = str(host_ip)
  host_keys = hosts.keys()
  for hk in host_keys:
    hi = get_host_ip(hk)
    if host_ip == hi: return hk
    
  return None
  
def get_host_by_ip(host_ip):
  """ Obtiene un objeto tipo host a partir de su ip """
  host_mac = get_host_mac(host_ip)
  if host_mac in hosts: return hosts[host_mac]
  else: return None
  
def get_host_by_mac(host_mac):
  """ Obtiene una referencia a un host a partir de una mac. Retorna None si no lo encuentra. """
  host_mac_str = str(host_mac)
  if host_mac_str in hosts: return hosts[host_mac_str]
  else: return None
  
def get_host_switch_port(host_mac , switch_id):
  """ Obtiene el puerto de un switch que esta conectado a un host """
  host_mac_str = str(host_mac)
  if host_mac_str not in hosts: return None
  host = hosts[host_mac_str]
  if host['switch_id'] == switch_id: return host['switch_port']
  else: return None
  

def get_switch_switch_link(switch_id , path):
  """ Obtiene un objeto tipo SIGUIENTE ENLACE de un switch dentro de un path diagramado.
  ej: get_switch_switch_link(2,[1, 2, 5, 3, 4]) -> Link(dpid1=2,port1=3, dpid2=5,port2=1) """
  if switch_id not in path: return None
  last_idx = len(path) - 1
  item_idx = path.index(switch_id)
  if item_idx == last_idx: return None
  next_switch_id = path[item_idx + 1]
  return adj[switch_id][next_switch_id]
  

# CONTROLLER CLASS ----------------------------------------------------------------------------------------
  
class ZgnFattreeController:
  def __init__ (self):  
    # Listen to dependencies
    def startup ():
      #core.openflow.addListeners(self, priority=0)
      core.openflow.addListeners(self)
      core.openflow_discovery.addListeners(self)        
      # Listen for flow stats
      core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
      # EL LISTENER DE ABAJO ES PARA UNA SOLUCION ALTERNATIVA DEL FIREWALL CON SOLICITUD DE ESTADISTICAS PERIODICAS.
      #core.openflow.addListenerByName("FlowStatsReceived", handle_udp_flow_stats)
      core.openflow.addListenerByName("FlowRemoved", handle_flow_removed)
      core.host_tracker.addListenerByName("HostEvent", handle_host_tracker_HostEvent)
      log.debug("ZgnFattreeController ESTA LISTO")
      
    core.call_when_ready(startup, ('openflow','openflow_discovery','host_tracker'))

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
      adj[l.dpid1][l.dpid2] = l
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
    # Cada switch tiene su propia BLACKLIST de firewalled-ips
    self.firewall_ips = set()
    
  
  def get_ports(self):
    return self.connection.ports
    
    
  def add_firewall_ip(self , ip_str):
    """ Agrega un ip string al set de ips bloqueads x firewall """
    self.firewall_ips.add(ip_str)
  
  def remove_firewall_ip(self , ip_str):
    """ Elimina un ip string del set de ips bloqueads x firewall """
    if ip_str in self.firewall_ips: 
      log.info("SWITCH_%s: QUITANDO %s DE LISTA NEGRA DE IPs bloqueadas" , self.switch_id ,ip_str)
      self.firewall_ips.remove(ip_str)
    
  def _handle_PacketIn (self, event):
    packet_in = event.ofp # objeto EVENTO de tipo PACKET_IN.
    packet = event.parsed
    
    src_mac = packet.src # MAC origen del paquete
    dst_mac = packet.dst # MAC destino del paquete
    in_port = packet_in.in_port # puerto de switch por donde ingreso el paquete
    
    # guardo la asociacion mac_origen -> puerto_entrada
    log.debug('SWITCH_%s: Asociando MAC %s a puerto de entrada %s' , self.switch_id , src_mac , in_port)
    self.mac_to_port[src_mac] = in_port
    
    eth_getNameForType = pkt.ETHERNET.ethernet.getNameForType(packet.type)
    # Parseo tempranamente los tipos de datos conocidos 
    pkt_is_ipv6 = eth_getNameForType == 'IPV6'
    icmp_pkt = packet.find('icmp')
    tcp_pkt = packet.find('tcp')
    udp_pkt = packet.find('udp')
    pkt_is_arp = packet.type == packet.ARP_TYPE
    ip_pkt = packet.find('ipv4')
    
    # Obtengo el nombre 'imprimible' del paquete
    pkt_type_name = eth_getNameForType
    if icmp_pkt : pkt_type_name = 'ICMP'
    if tcp_pkt : pkt_type_name = 'TCP'
    if udp_pkt : pkt_type_name = 'UDP'
    if pkt_is_arp : pkt_type_name = 'ARP'
    
    def build_flow_key():
      """ Crea la clave de un flujo a partir de campos disponibles del paquete procesado """
      flow_key = pkt_type_name + '#'
      if ip_pkt: flow_key += str(ip_pkt.srcip) + 'to' + str(ip_pkt.dstip)
      if tcp_pkt: flow_key += ':' + str(tcp_pkt.dstport) + "-" + str(tcp_pkt.ACK)
      # TODO ... PARA UDP SE DEBEN CONSTRUIR FLUJOS DISTINTOS PARA LA IDA Y LA VUELTA... CONSIDERAR USAR LA MAC
      if udp_pkt: flow_key += ':' + str(udp_pkt.dstport)
      if icmp_pkt: flow_key += '-' + str(icmp_pkt.type)
      log.info("SWITCH_%s: flow_key = %s" , self.switch_id , flow_key)
      return flow_key
    
    def install_flow(out_port , duration = FLOW_INSTALL_DURATION):
      """ Instala un flujo en el switch del tipo MAC_ORIGEN@PUERTO_ENTRADA -> MAC_DESTINO@PUERTO_SALIDA """
      if not pkt_is_arp:
        log.info("SWITCH_%s: Instale un flujo de %s@PUERTO_%i hacia %s@PUERTO_%i de tipo %s" % 
          (self.switch_id,src_mac, in_port, dst_mac, out_port , pkt_type_name))
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, in_port)
      msg.idle_timeout = duration
      msg.hard_timeout = duration
      msg.actions.append(of.ofp_action_output(port = out_port))
      msg.data = packet_in
      # OFPFF_SEND_FLOW_REM indica al switch que debe notificar al controlador cuando un flujo haya sido dado de baja. Ver funcion handle_flow_removed
      # OFPFF_CHECK_OVERLAP pide al switch que verifique overlap de reglas de flujo
      msg.flags = of.OFPFF_SEND_FLOW_REM + of.OFPFF_CHECK_OVERLAP
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
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Enviar el paquete a la NADA
        self.connection.send(msg)
      elif packet_in.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = packet_in.buffer_id
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Enviar el paquete a la NADA
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
      # NOTA : dado que instalar un flujo demora tiempo, handle_all se esta llamando multiples veces...
      # si el puerto de salida se encuentra en la tabla de MACs entonces instalo un flujo en el switch
      if dst_mac in self.mac_to_port:
        out_port = self.mac_to_port[dst_mac]
        install_flow(out_port)
      else:
        flood()
        
    def handle_dhcp():
      """ Maneja paquetes DHCP ... Pensar si acaso deberian dropearse... """
      dstip = ip_pkt.dstip
      log.debug('MANEJANDO PAQUETE DHCP HACIA IP %s' % str(dstip) )
      handle_all()
      
    def install_path_flow(out_port , duration=FLOW_INSTALL_DURATION):
      """ Instala un flujo selectivo a partir de un path """
      log.info("SWITCH_%s: Instalando flujo a partir de path %s@PUERTO_%i -> %s@PUERTO_%i de tipo %s" % 
        (self.switch_id,src_mac, in_port, dst_mac, out_port , pkt_type_name))
      msg = of.ofp_flow_mod()
      
      if udp_pkt:
        udp_dst_port = udp_pkt.dstport
        msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=UDP_nw_proto, tp_dst=udp_dst_port)
      elif tcp_pkt:
        tcp_dst_port = tcp_pkt.dstport
        msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=TCP_nw_proto, tp_dst=tcp_dst_port)
      else:
        msg.match = of.ofp_match(dl_type=IP_dl_type, nw_proto=ICMP_nw_proto)
      str_dst_ip = ip_pkt.dstip
      msg.match.set_nw_dst( str_dst_ip , 32)
      
      msg.idle_timeout = duration
      msg.hard_timeout = duration
      msg.actions.append(of.ofp_action_output(port = out_port))
      msg.data = packet_in
      # OFPFF_SEND_FLOW_REM indica al switch que debe notificar al controlador cuando un flujo haya sido dado de baja. Ver funcion handle_flow_removed
      # OFPFF_CHECK_OVERLAP pide al switch que verifique overlap de reglas de flujo
      msg.flags = of.OFPFF_SEND_FLOW_REM + of.OFPFF_CHECK_OVERLAP
      self.connection.send(msg)
    
    def handle_ip_complex():
      """ Maneja paquetes tipo ip """
      dst_mac_str = str(dst_mac) # obtengo el string de mac destino
      log.info("SWITCH_%s: Mac destino es %s" , self.switch_id , dst_mac_str)
      
      # si el host destino es desconocido, entonces me falta conocer a mas hosts y manejo el paquete como un switch bobo
      if dst_mac_str not in hosts: return handle_all()
      
      host_switch_port = get_host_switch_port(dst_mac_str , self.switch_id)
      # si la mac destino es de un host y este switch esta directamente conectado al mismo, entonces instalo un flujo inmediatamente
      if host_switch_port is not None: 
        log.info('SWITCH_%s: La Mac destino %s corresponde a un host conectado a MI puerto %d!' , self.switch_id , dst_mac_str , host_switch_port)
        return install_flow(host_switch_port)
      
      # TODOOOOOOOOOO : VERIFICAR SI ACASO SE DEBE USAR install_flow EN VEZ DE install_path_flow
      
      # verifico si ya existe un path asignado a este flujo
      flow_key = build_flow_key()
      if flow_key in current_paths:
        path = current_paths[flow_key]
        log.info('SWITCH_%s: el path %s esta asignado al flow_key %s' , self.switch_id , str(path) , flow_key )
        # instalo un flujo para forwardear el paquete
        switch_switch_link = get_switch_switch_link(self.switch_id , path)
        if switch_switch_link is not None:
          out_port = switch_switch_link.port1
          log.info("SWITCH_%s: El paquete debe salir por mi puerto %d" , self.switch_id , out_port)
          return install_flow(out_port)
          #return install_path_flow(out_port)
        else:
          log.warn('SWITCH_%s: encontre un path... pero yo no tengo enlace ALGO ESTA MAL' , self.switch_id)
          return handle_all()
          
      # si llegue a este punto es porque no hay un path asignado al camino indicado... probablemente este switch es de borde
      # debo solicitar un camino libre y asignarlo
      host = get_host_by_mac(dst_mac)
      if host is not None:
        end_switch_id = host['switch_id'] # obtengo el id del switch al cual esta conectado el host destino
        # busco o bien un camino libre o cualquier camino en caso de no existir ninguno libre
        log.info("SWITCH_%s: Busco un path hacia switch %s" , self.switch_id , end_switch_id)
        path = find_non_taken_path(self.switch_id , end_switch_id)
        if path is None:
          path = find_any_path(self.switch_id , end_switch_id)
        path_str = str(path)
        log.info("SWITCH_%s: Voy a usar el path %s y se lo asigno al flujo %s" , self.switch_id , path_str , flow_key)
        # guardo la asociacion entre la clave del flujo y el path encontrado
        current_paths[flow_key] = path
        # marco al path encontrado como TOMADO
        taken_paths.add( path_str )
        # incremento la cantidad de veces que el camino esta siendo usado
        current_paths_load[path_str] += 1
        # instalo un flujo para forwardear el paquete
        switch_switch_link = get_switch_switch_link(self.switch_id , path)
        if switch_switch_link is not None:
          out_port = switch_switch_link.port1
          install_flow(out_port)
          #return install_path_flow(out_port)
          def remove_taken_path():
            log.info("SWITCH_%s: ELIMINANDO PATH %s DE FLUJO %s" , self.switch_id , path_str , flow_key)
            if path_str in taken_paths: taken_paths.remove( path_str )
            if flow_key in current_paths: current_paths.pop( flow_key )
            current_paths_load[path_str] -= 1
          # despues de un tiempo elimino el path de flujo instalado
          Timer(FLOW_INSTALL_DURATION, remove_taken_path)
          return True
          
        else:
          log.warn('SWITCH_%s: encontre un path... pero yo no tengo enlace ALGO ESTA MAL' , self.switch_id)
          return handle_all()
        
      # condicion fallback ... manejo el paquete como puedo
      handle_all()
    
    def handle_ip():
      if HANDLE_IP_COMPLEX: return handle_ip_complex()
      else: return handle_all()
    
    def handle_udp():
      """ Maneja paquetes UDP. Si detecta que un destino esta bloqueado por un firewall, descarta el paquete """
      dstip = ip_pkt.dstip
      str_dst_ip = str(dstip)
      if str_dst_ip in self.firewall_ips:
        log.info('SWITCH_%s PAQUETES CON DESTINO %s SIGUEN BLOQUEADOS... REALIZANDO DROP' , self.switch_id , str_dst_ip)
        drop()
        return
      dstport = udp_pkt.dstport
      if dstport == DHCP_PORT : return handle_dhcp()
      handle_ip()  
    
    def handle_unknown():
      """ Maneja un paquete de tipo desconocido """
      log.debug('PAQUETE DESCONOCIDO DETECTADO DE TIPO %s::%s' , eth_getNameForType , pkt_type_name)
      # TODO : VER QUE ES MEJOR , SI MANEJAR LOS PAQUETES DESCONOCIDOS O SI DROPEARLOS
      drop(30)
      #handle_all()
    
    # LOS PAQUETES DESCONOCIDOS SON DROPEADOS. POR AHORA IGNORAMOS LOS PAQUETES IPV6
    # DADO QUE ESTAMOS USANDO host_tracker, DEBEMOS MANEJAR LOS PAQUETES ARP (NO DROPEAR)
    unknown_pkt = pkt_is_ipv6 or ( icmp_pkt is None and tcp_pkt is None and udp_pkt is None and not pkt_is_arp )
    if unknown_pkt: return handle_unknown()
    
    # los paquetes ARP los despacho inmediatamente sin crear ni reservar flujos
    if pkt_is_arp: return handle_all()
    
    log.debug('SWITCH_%s@PORT_%d LLEGO PAQUETE TIPO %s::%s MAC_ORIGEN: %s MAC_DESTINO: %s' % 
      (self.switch_id,in_port,eth_getNameForType,pkt_type_name,src_mac,dst_mac))

    # por alguna razon bizarra... esta linea rompe
    # si la mac es ff:ff:ff:ff:ff:ff entonces hago un flood
    #if dst_mac.is_multicast: flood()
      
    # si el mac origen es igual al mac destino entonces dropeo
    if src_mac == dst_mac: 
      log.info("SWITCH_%s: MAC ORIGEN ES IGUAL A MAC DESTINO!" , self.switch_id)
      drop()
      
    if udp_pkt: return handle_udp()
    
    if ip_pkt: return handle_ip()
    
    handle_all()

    
# launch ----------------------------------------------------------------------------------------------------------------------



def launch (flow_duration = 10 , udp_fwall_pkts = 100 , fwall_duration = 10):
  pox.log.color.launch()
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")  
  
  # Los parametros de configuracion pueden pasarse como --nombre_parametro=VALOR inmediatamente luego del nombre de ESTE MODULO.
  global FLOW_INSTALL_DURATION
  FLOW_INSTALL_DURATION = int(flow_duration)
  log.info("DURACION DE FLUJOS: %s SEGUNDOS" , FLOW_INSTALL_DURATION)
  
  global UDP_FIREWALL_THRESHOLD
  UDP_FIREWALL_THRESHOLD = int(udp_fwall_pkts)
  log.info("CANTIDAD DE PAQUETES UDP LIMITE P/FIREWALL: %s PAQUETES" , UDP_FIREWALL_THRESHOLD)
  
  # Duracion base del firewall. Se renueva cada FIREWALL_DURATION segundos (si es necesario).
  global FIREWALL_DURATION
  FIREWALL_DURATION = int(fwall_duration)
  log.info("DURACION DEL FIREWALL: %s SEGUNDOS" , FIREWALL_DURATION)
  
  pox.openflow.discovery.launch()
  
  # no_flood: If True, we set ports down when a switch connects
  # hold_down: If True, don't allow turning off flood bits until a complete discovery cycle should have completed (mostly makes sense with _noflood_by_default).
  pox.openflow.spanning_tree.launch(no_flood = True, hold_down = True)
  
  # --arpAware=15 --arpSilent=45 --arpReply=1 --entryMove=4
  host_tracker.launch(arpAware=15 , arpSilent=45 , entryMove=4)
  
  
  core.registerNew(ZgnFattreeController)
  
  # Estas lineas de abajo exponen las variables adj y switch_ids al modulo interactivo de pox 'PY'
  core.Interactive.variables['adj'] = adj
  core.Interactive.variables['switch_ids'] = switch_ids
  core.Interactive.variables['switches'] = switches
  core.Interactive.variables['stats'] = request_flow_stats
  core.Interactive.variables['all_stats'] = request_all_flow_stats
  core.Interactive.variables['hosts'] = hosts
  core.Interactive.variables['mac_entries'] = get_host_tracker_entries
  core.Interactive.variables['host_ip'] = get_host_ip
  core.Interactive.variables['host_mac'] = get_host_mac
  core.Interactive.variables['find_switch_path'] = find_switch_path
  core.Interactive.variables['get_switch_switch_link'] = get_switch_switch_link
  core.Interactive.variables['set_ip_complex'] = set_ip_complex
  core.Interactive.variables['taken_paths'] = taken_paths
  core.Interactive.variables['current_paths'] = current_paths
  core.Interactive.variables['current_paths_load'] = current_paths_load
  core.Interactive.variables['set_udp_firewall_thresh'] = set_udp_firewall_thresh
  
  
  # AVERIGUAR PARA QUE SIRVE WaitingPath EN l2_multi
  #timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  #Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)


  
pox.openflow.spanning_tree.launch()
